# Protocol (API v1)

All endpoints are under `/api/v1`. JSON in and out, except database content (`application/octet-stream`).
Authenticated endpoints need `Authorization: Bearer <token>`. A running server serves an OpenAPI 3.1 description at
`/api/openapi.json` and renders it at `/api/docs` (source: `src/openapi.ts`). Errors look like:

```json
{ "error": { "code": "conflict", "message": "…", "currentRevision": 7 } }
```

## Connect & test

A "Test connection" button does:

1. `GET /status` (no auth) → `{ "server": "keepass-server", "apiVersion": 1 }`. Anything else: wrong URL.
2. `POST /auth/login` `{ username, password, deviceName }` → `{ token, user }`. `401` wrong credentials,
   `429` throttled (`retryAfterSeconds`).
3. Optional: `GET /vaults/:id` → `role` must be `owner` or `editor` to save.

The reference implementation is `KpsApi.testConnection` in `client/api.ts`.

## Endpoints

| Method | Path | |
|---|---|---|
| GET | `/status` | Server identification (public) |
| POST | `/auth/login` | → device token |
| POST | `/auth/logout` | Revoke the current token |
| GET | `/me` | Current user |
| POST | `/me/password` | `{ currentPassword, newPassword }`, signs out other devices |
| GET / DELETE | `/me/tokens`, `/me/tokens/:id` | Signed-in devices |
| GET / POST | `/users` | Admin: list / create `{ username, password, isAdmin }` |
| PATCH / DELETE | `/users/:id` | Admin: `{ password?, isAdmin?, disabled? }` |
| GET / POST | `/groups` | List (admin: all, others: own groups) / admin: create `{ name, members?: [username] }` |
| GET / PATCH / DELETE | `/groups/:id` | Info (admin or member) / admin: rename `{ name }` / admin: delete |
| PUT / DELETE | `/groups/:id/members/:username` | Admin: add / remove a group member |
| GET | `/vaults` | Vaults visible to the caller, with `revision`, `role`, `conflicts` |
| POST | `/vaults` | `{ name, groups?: [{ name, role }] }` → new empty vault (revision 0), caller is owner, optionally shared with groups |
| GET / PATCH / DELETE | `/vaults/:id` | Info / rename (owner) / delete (owner) |
| GET, HEAD | `/vaults/:id/content` | Current database. `ETag: "<rev>"`, `X-KPS-Revision`, `X-KPS-SHA256`. `If-None-Match: "<rev>"` → `304`. Empty vault → `404 empty_vault` |
| PUT | `/vaults/:id/content` | Upload. **Requires** `If-Match: "<base rev>"` (`"0"` for the first upload, `*` = force). Optional `X-KPS-SHA256`, `X-KPS-Note` (URL-encoded). `201` new revision, `200` unchanged, `412` conflict, `422` not a KDBX file |
| GET | `/vaults/:id/wait?since=<rev>&timeout=25` | Long-poll; returns `{ revision, changed }` as soon as the revision differs from `since` |
| GET | `/vaults/:id/revisions` | History |
| GET | `/vaults/:id/revisions/:rev/content` | Download an old revision |
| POST | `/vaults/:id/revisions/:rev/restore` | Make an old revision current (creates a new revision) |
| GET / POST | `/vaults/:id/conflicts` | List / store a conflict copy (body = kdbx, `X-KPS-Base-Revision`, `X-KPS-Reason`) |
| GET | `/vaults/:id/conflicts/:cid/content` | Download a conflict copy |
| DELETE | `/vaults/:id/conflicts/:cid` | Mark resolved |
| GET | `/vaults/:id/members` | Members and roles |
| PUT / DELETE | `/vaults/:id/members/:username` | Owner: `{ role }` / remove. The last owner can't be removed |
| GET | `/vaults/:id/groups` | Groups with access and their roles |
| PUT / DELETE | `/vaults/:id/groups/:name` | Owner: give a group `{ role }` / remove its access |

Vaults the caller cannot see return `404`, never `403`.

A user's `role` on a vault is the highest of their direct role and the roles of their groups.

## Client sync algorithm

State per vault, stored next to the cached file: `baseRevision`, `baseSha256`, `dirty`, `workOffline`.

```
open():   open the local cache (no network needed)
save():   write the cache, dirty = true, then sync() in the background

sync():
  if workOffline: return
  if not dirty:
      GET content with If-None-Match: "<baseRevision>"
      304            → up to date
      200            → replace cache, baseRevision = X-KPS-Revision, reload the open database
  else repeat up to 5 times:
      PUT content with If-Match: "<baseRevision>", X-KPS-SHA256
      201/200        → baseRevision = revision, dirty = false, done
      412            → GET content (newest), open it with the same key
                         ok          → merge remote into local, save cache, baseRevision = remote rev, retry PUT
                         wrong key   → POST conflicts (local file), keep a local copy,
                                       replace cache with remote, dirty = false,
                                       ask the user to unlock with the new key
      403            → read-only access: keep local changes, tell the user
  network error / 5xx → keep dirty, retry later (connectivity change, timer, app start)
```

Live updates: while a database is open, loop on `GET /vaults/:id/wait?since=<baseRevision>`; when `changed`,
run `sync()`.

Reference implementation: `client/sync.ts` (`LocalVault`), tested in `test/sync.test.ts`.
