// OpenAPI 3.1 description of API v1, served at /api/openapi.json and rendered at /api/docs.
// test/server.test.ts checks that every route in api.ts is described here and vice versa.

import { API_VERSION } from './api.ts';

type Schema = Record<string, unknown>;

const ref = (name: string): Schema => ({ $ref: `#/components/schemas/${name}` });
const arrayOf = (items: Schema): Schema => ({ type: 'array', items });
const obj = (properties: Record<string, Schema>, required: string[] = Object.keys(properties)): Schema =>
  ({ type: 'object', properties, required });
const str: Schema = { type: 'string' };
const int: Schema = { type: 'integer' };
const bool: Schema = { type: 'boolean' };
const date: Schema = { type: 'string', format: 'date-time' };
const nullable = (s: Schema): Schema => ({ ...s, type: [s.type, 'null'] });

const json = (schema: Schema) => ({ content: { 'application/json': { schema } } });
const kdbx = { content: { 'application/octet-stream': { schema: { type: 'string', format: 'binary' } } } };
const ok = (description: string, schema: Schema) => ({ description, ...json(schema) });
const err = (description: string) => ({ description, ...json(ref('Error')) });
const body = (schema: Schema) => ({ required: true, ...json(schema) });

const path = (name: string, description: string, schema: Schema = str) => ({ name, in: 'path', required: true, description, schema });
const header = (name: string, description: string, required = false) => ({ name, in: 'header', required, description, schema: str });
const P = {
  vault: path('id', 'Vault id'),
  user: path('id', 'User id', int),
  group: path('id', 'Group id', int),
  token: path('id', 'Token id', int),
  username: path('username', 'Username'),
  groupName: path('name', 'Group name'),
  rev: path('rev', 'Revision number', int),
  conflict: path('cid', 'Conflict copy id'),
};

const OK = { 200: ok('Done', ref('Ok')) };
const UNAUTHORIZED = { 401: err('Missing, invalid, expired or revoked token') };
const ADMIN_ONLY = { ...UNAUTHORIZED, 403: err('Administrator only') };
const NO_VAULT = { ...UNAUTHORIZED, 404: err('Vault not found (also when the caller cannot see it)') };
const VAULT_ROLE = (role: string) => ({ ...NO_VAULT, 403: err(`Needs the ${role} role on the vault`) });

const schemas: Record<string, Schema> = {
  Error: obj({
    error: { type: 'object', required: ['code', 'message'], additionalProperties: true, properties: { code: str, message: str } },
  }),
  Ok: obj({ ok: { const: true } }),
  Role: { type: 'string', enum: ['owner', 'editor', 'reader'] },
  User: obj({ id: int, username: str, isAdmin: bool, disabled: bool, createdAt: date }),
  Token: obj({ id: int, deviceName: str, current: bool, createdAt: date, lastUsedAt: date, expiresAt: date }),
  Group: obj({ id: int, name: str, createdAt: date, members: arrayOf(obj({ userId: int, username: str })) }),
  Vault: obj({
    id: str, name: str, role: ref('Role'), revision: int, sha256: nullable(str), size: nullable(int),
    createdAt: date, updatedAt: nullable(date), conflicts: { ...int, description: 'Number of unresolved conflict copies' },
  }),
  CommitResult: obj({ revision: int, sha256: str, unchanged: { ...bool, description: 'Upload was identical to the current revision' } }),
  Revision: obj({
    revision: int, sha256: str, size: int, createdAt: date, username: nullable(str), deviceName: nullable(str),
    baseRevision: nullable(int), note: nullable(str), current: bool,
  }),
  Conflict: obj({
    id: str, sha256: str, size: int, createdAt: date, username: nullable(str), deviceName: nullable(str),
    baseRevision: nullable(int), reason: nullable(str),
  }),
  Member: obj({ userId: int, username: str, role: ref('Role') }),
  VaultGroup: obj({ groupId: int, name: str, role: ref('Role') }),
};

const paths: Record<string, Record<string, Schema>> = {
  '/status': {
    get: {
      tags: ['Auth'], summary: 'Server identification', security: [],
      responses: { 200: ok('Server info', obj({ server: { const: 'keepass-server' }, apiVersion: int, time: date })) },
    },
  },
  '/auth/login': {
    post: {
      tags: ['Auth'], summary: 'Log in and get a device token', security: [],
      description: 'The returned token is sent as `Authorization: Bearer <token>`. It expires after `KPS_TOKEN_TTL_DAYS` days without use.',
      requestBody: body(obj({ username: str, password: str, deviceName: { ...str, description: 'Shown under Account → signed-in devices' } }, ['username', 'password'])),
      responses: {
        200: ok('Logged in', obj({ token: str, user: ref('User') })),
        401: err('Wrong username or password, or the account is disabled'),
        429: err('Too many failed logins (`retryAfterSeconds`)'),
      },
    },
  },
  '/auth/logout': {
    post: { tags: ['Auth'], summary: 'Revoke the current token', responses: { ...OK, ...UNAUTHORIZED } },
  },
  '/me': {
    get: {
      tags: ['Account'], summary: 'Current user',
      responses: { 200: ok('Current user', { allOf: [ref('User'), obj({ deviceName: str })] }), ...UNAUTHORIZED },
    },
  },
  '/me/password': {
    post: {
      tags: ['Account'], summary: 'Change password (signs out other devices)',
      requestBody: body(obj({ currentPassword: str, newPassword: { ...str, minLength: 10 } })),
      responses: { ...OK, 400: err('New password too weak'), ...UNAUTHORIZED, 403: err('Current password is wrong') },
    },
  },
  '/me/tokens': {
    get: { tags: ['Account'], summary: 'Signed-in devices', responses: { 200: ok('Tokens', arrayOf(ref('Token'))), ...UNAUTHORIZED } },
  },
  '/me/tokens/{id}': {
    delete: { tags: ['Account'], summary: 'Sign out a device', parameters: [P.token], responses: { ...OK, ...UNAUTHORIZED, 404: err('Token not found') } },
  },
  '/users': {
    get: { tags: ['Users'], summary: 'List users (admin)', responses: { 200: ok('Users', arrayOf(ref('User'))), ...ADMIN_ONLY } },
    post: {
      tags: ['Users'], summary: 'Create a user (admin)',
      requestBody: body(obj({ username: str, password: { ...str, minLength: 10 }, isAdmin: bool }, ['username', 'password'])),
      responses: { 201: ok('Created', ref('User')), 400: err('Invalid username or password'), ...ADMIN_ONLY, 409: err('Username already taken') },
    },
  },
  '/users/{id}': {
    patch: {
      tags: ['Users'], summary: 'Change a user (admin)', parameters: [P.user],
      description: 'A new password or disabling the user signs out all of their devices.',
      requestBody: body(obj({ password: str, isAdmin: bool, disabled: bool }, [])),
      responses: { 200: ok('Updated', ref('User')), ...ADMIN_ONLY, 404: err('User not found'), 409: err('Last administrator or own account') },
    },
    delete: {
      tags: ['Users'], summary: 'Delete a user (admin)', parameters: [P.user],
      responses: { ...OK, ...ADMIN_ONLY, 404: err('User not found'), 409: err('Own account, last administrator, or sole owner of vaults (`vaults`)') },
    },
  },
  '/groups': {
    get: { tags: ['Groups'], summary: 'List groups (admin: all, others: their own)', responses: { 200: ok('Groups', arrayOf(ref('Group'))), ...UNAUTHORIZED } },
    post: {
      tags: ['Groups'], summary: 'Create a group (admin)',
      requestBody: body(obj({ name: str, members: { ...arrayOf(str), description: 'Usernames' } }, ['name'])),
      responses: { 201: ok('Created', ref('Group')), ...ADMIN_ONLY, 404: err('Unknown member'), 409: err('Group name already taken') },
    },
  },
  '/groups/{id}': {
    get: { tags: ['Groups'], summary: 'Group info (admin or member)', parameters: [P.group], responses: { 200: ok('Group', ref('Group')), ...UNAUTHORIZED, 404: err('Group not found') } },
    patch: {
      tags: ['Groups'], summary: 'Rename a group (admin)', parameters: [P.group], requestBody: body(obj({ name: str })),
      responses: { 200: ok('Renamed', ref('Group')), ...ADMIN_ONLY, 404: err('Group not found'), 409: err('Group name already taken') },
    },
    delete: { tags: ['Groups'], summary: 'Delete a group (admin)', parameters: [P.group], responses: { ...OK, ...ADMIN_ONLY, 404: err('Group not found') } },
  },
  '/groups/{id}/members/{username}': {
    put: { tags: ['Groups'], summary: 'Add a member (admin)', parameters: [P.group, P.username], responses: { 200: ok('Group', ref('Group')), ...ADMIN_ONLY, 404: err('Group or user not found') } },
    delete: { tags: ['Groups'], summary: 'Remove a member (admin)', parameters: [P.group, P.username], responses: { 200: ok('Group', ref('Group')), ...ADMIN_ONLY, 404: err('Group, user or membership not found') } },
  },
  '/vaults': {
    get: { tags: ['Vaults'], summary: 'Vaults visible to the caller', responses: { 200: ok('Vaults', arrayOf(ref('Vault'))), ...UNAUTHORIZED } },
    post: {
      tags: ['Vaults'], summary: 'Create an empty vault (revision 0); the caller becomes owner',
      requestBody: body(obj({ name: str, groups: arrayOf(obj({ name: str, role: ref('Role') })) }, ['name'])),
      responses: { 201: ok('Created', ref('Vault')), ...UNAUTHORIZED, 404: err('Group not found') },
    },
  },
  '/vaults/{id}': {
    get: { tags: ['Vaults'], summary: 'Vault info', parameters: [P.vault], responses: { 200: ok('Vault', ref('Vault')), ...NO_VAULT } },
    patch: { tags: ['Vaults'], summary: 'Rename (owner)', parameters: [P.vault], requestBody: body(obj({ name: str })), responses: { 200: ok('Vault', ref('Vault')), ...VAULT_ROLE('owner') } },
    delete: { tags: ['Vaults'], summary: 'Delete (owner)', parameters: [P.vault], responses: { ...OK, ...VAULT_ROLE('owner') } },
  },
  '/vaults/{id}/content': {
    get: {
      tags: ['Content'], summary: 'Download the current database',
      parameters: [P.vault, header('If-None-Match', '`"<rev>"` → `304` when unchanged')],
      responses: {
        200: { description: 'The .kdbx file. Headers: `ETag: "<rev>"`, `X-KPS-Revision`, `X-KPS-SHA256`', ...kdbx },
        304: { description: 'Not modified' }, ...NO_VAULT,
      },
    },
    put: {
      tags: ['Content'], summary: 'Upload a new revision (editor)',
      parameters: [
        P.vault,
        header('If-Match', 'Revision the upload is based on: `"0"` for the first upload, `*` to force', true),
        header('X-KPS-SHA256', 'Optional SHA-256 of the body, verified by the server'),
        header('X-KPS-Note', 'Optional URL-encoded note'),
      ],
      requestBody: { required: true, ...kdbx },
      responses: {
        201: ok('New revision', ref('CommitResult')), 200: ok('Identical to the current revision', ref('CommitResult')),
        ...VAULT_ROLE('editor'), 412: err('Conflict: the vault changed (`currentRevision`); download, merge, upload again'),
        413: err('Too large'), 422: err('Not a KDBX file'), 428: err('If-Match missing'),
      },
    },
  },
  '/vaults/{id}/wait': {
    get: {
      tags: ['Content'], summary: 'Long-poll until the revision differs from `since`',
      parameters: [
        P.vault,
        { name: 'since', in: 'query', description: 'Known revision (default: current)', schema: int },
        { name: 'timeout', in: 'query', description: 'Seconds, 1–60', schema: { ...int, default: 25 } },
      ],
      responses: { 200: ok('Current revision', obj({ revision: int, changed: bool })), ...NO_VAULT },
    },
  },
  '/vaults/{id}/revisions': {
    get: { tags: ['Revisions'], summary: 'History', parameters: [P.vault], responses: { 200: ok('Revisions', arrayOf(ref('Revision'))), ...NO_VAULT } },
  },
  '/vaults/{id}/revisions/{rev}/content': {
    get: { tags: ['Revisions'], summary: 'Download an old revision', parameters: [P.vault, P.rev], responses: { 200: { description: 'The .kdbx file', ...kdbx }, ...NO_VAULT } },
  },
  '/vaults/{id}/revisions/{rev}/restore': {
    post: { tags: ['Revisions'], summary: 'Make an old revision current (editor)', parameters: [P.vault, P.rev], responses: { 201: ok('New revision', ref('CommitResult')), ...VAULT_ROLE('editor') } },
  },
  '/vaults/{id}/conflicts': {
    get: { tags: ['Conflicts'], summary: 'Conflict copies', parameters: [P.vault], responses: { 200: ok('Conflicts', arrayOf(ref('Conflict'))), ...NO_VAULT } },
    post: {
      tags: ['Conflicts'], summary: 'Store a conflict copy (editor)',
      parameters: [P.vault, header('X-KPS-Base-Revision', 'Revision the copy was based on'), header('X-KPS-Reason', 'URL-encoded reason')],
      requestBody: { required: true, ...kdbx },
      responses: { 201: ok('Stored', obj({ id: str })), ...VAULT_ROLE('editor') },
    },
  },
  '/vaults/{id}/conflicts/{cid}/content': {
    get: { tags: ['Conflicts'], summary: 'Download a conflict copy', parameters: [P.vault, P.conflict], responses: { 200: { description: 'The .kdbx file', ...kdbx }, ...NO_VAULT } },
  },
  '/vaults/{id}/conflicts/{cid}': {
    delete: { tags: ['Conflicts'], summary: 'Mark resolved (editor)', parameters: [P.vault, P.conflict], responses: { ...OK, ...VAULT_ROLE('editor') } },
  },
  '/vaults/{id}/members': {
    get: { tags: ['Sharing'], summary: 'Members and roles', parameters: [P.vault], responses: { 200: ok('Members', arrayOf(ref('Member'))), ...NO_VAULT } },
  },
  '/vaults/{id}/members/{username}': {
    put: {
      tags: ['Sharing'], summary: 'Add a member or change their role (owner)', parameters: [P.vault, P.username],
      requestBody: body(obj({ role: ref('Role') })),
      responses: { 200: ok('Saved', obj({ username: str, role: ref('Role') })), ...VAULT_ROLE('owner'), 409: err('A vault needs at least one owner') },
    },
    delete: { tags: ['Sharing'], summary: 'Remove a member (owner)', parameters: [P.vault, P.username], responses: { ...OK, ...VAULT_ROLE('owner'), 409: err('A vault needs at least one owner') } },
  },
  '/vaults/{id}/groups': {
    get: { tags: ['Sharing'], summary: 'Groups with access', parameters: [P.vault], responses: { 200: ok('Groups', arrayOf(ref('VaultGroup'))), ...NO_VAULT } },
  },
  '/vaults/{id}/groups/{name}': {
    put: {
      tags: ['Sharing'], summary: 'Give a group a role (owner)', parameters: [P.vault, P.groupName],
      requestBody: body(obj({ role: ref('Role') })),
      responses: { 200: ok('Saved', ref('VaultGroup')), ...VAULT_ROLE('owner') },
    },
    delete: { tags: ['Sharing'], summary: 'Remove a group\'s access (owner)', parameters: [P.vault, P.groupName], responses: { ...OK, ...VAULT_ROLE('owner') } },
  },
};

// operationId from method and path, e.g. GET /vaults/{id} → getVaultsById, PUT /vaults/{id}/members/{username} → putVaultsMembersByUsername.
for (const [p, ops] of Object.entries(paths)) {
  for (const [method, op] of Object.entries(ops)) {
    const words = p.split('/').filter(Boolean).filter((w, i, all) => w !== '{id}' || i === all.length - 1)
      .map((w) => (w.startsWith('{') ? `By-${w.slice(1, -1)}` : w))
      .flatMap((w) => w.split('-'));
    op.operationId = method + words.map((w) => w[0]!.toUpperCase() + w.slice(1)).join('');
  }
}

export const openApiSpec = {
  openapi: '3.1.0',
  info: {
    title: 'KeePass Server API',
    version: String(API_VERSION),
    description: 'Sync API for encrypted .kdbx databases. Get a token with `POST /auth/login` and send it as `Authorization: Bearer <token>`. '
      + 'See docs/PROTOCOL.md for the client sync algorithm.',
  },
  servers: [{ url: `/api/v${API_VERSION}` }],
  security: [{ bearer: [] }],
  components: { securitySchemes: { bearer: { type: 'http', scheme: 'bearer' } }, schemas },
  paths,
};
