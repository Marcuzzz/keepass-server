# Design

## What the server stores: whole `.kdbx` files

The unit of storage is the encrypted `.kdbx` file, exactly as KeePassXC, KeePassDX or KeePass write it. The
server never decrypts it and has no access to master passwords or key files.

Why not store entries as rows in a database? That would give per-entry sync on the server, but the server
would then need to read entries, which means either:

- the server holds the master key, so a server breach leaks every password, or
- a new per-entry encryption format that no KeePass client understands, which means rewriting every client and
  losing the "it's just a `.kdbx` file" property (backups, export, opening it in any KeePass app).

Per-entry conflict resolution is still possible without either, because the `.kdbx` format already carries
what is needed: every entry and group has a UUID, a modification time and a history, and deletions are
recorded as tombstones (`DeletedObjects`). The KeePass merge (KeePassXC `Merger`, KeePassDX
`DatabaseKDBXMerger`, kdbxweb `Kdbx.merge`) uses those to combine two versions entry by entry. The merge
happens on the client, which has the key.

## Comparison with Joplin

Joplin Server with end-to-end encryption works the same way at its core: the server stores encrypted items
it can't read, and clients sync and resolve conflicts.

| | Joplin | keepass-server |
|---|---|---|
| Unit of sync | one encrypted item per note/notebook | one encrypted `.kdbx` per vault |
| Change detection | per item `updated_time` + delta API | per vault revision number (ETag) |
| Conflict detection | client compares item timestamps | server refuses stale uploads (`412`) |
| Conflict resolution | the losing note is copied to a "Conflicts" notebook | KeePass merge per entry, the older version goes to entry history |
| When merging is impossible | — | the whole local file is stored as a *conflict copy* on the server |
| Offline | local SQLite is the source of truth, sync later | local `.kdbx` cache is the source of truth, sync later |

So the answer to "same type of database?" is **yes**: keep `.kdbx`. It works with the existing apps, stays
end-to-end encrypted, and its merge handles conflicts per entry like Joplin does per note.

## Revisions and optimistic concurrency

Each vault has a revision counter. `GET content` returns the current revision as the `ETag`. `PUT content`
must send `If-Match: "<revision the changes are based on>"`:

- still current → stored as revision + 1;
- someone else uploaded first → `412 conflict` with the current revision; the client downloads it, merges, and
  retries;
- identical to the current content → `200 unchanged` (makes retries after a lost response harmless);
- no `If-Match` at all → `428`, so a client that does not do conflict handling cannot overwrite anything.

The check-and-insert runs synchronously inside one SQLite transaction after the upload is on disk, so two
uploads based on the same revision can never both succeed (covered by a test).

Uploads are also verified: the body must start with the KDBX 3/4 signature (rejects truncated uploads, proxy
error pages, …) and match `X-KPS-SHA256` when the client sends it.

## Conflict layers

1. **Merge** (normal case). Different entries changed: both kept. Same entry changed on both sides: the newer
   edit wins and the other one is kept in that entry's history. Deletions propagate through tombstones.
2. **Conflict copy** (merge impossible, e.g. the master key was changed on another device). The client uploads
   its local file to `POST /vaults/:id/conflicts`, keeps a local copy, and continues with the server version.
   Users see a badge in the web UI and in clients, download the copy, open it with its old key and use
   KeePass *Merge/Synchronize*, then delete the copy.
3. **Revisions**. Any earlier version can be downloaded or restored (restore creates a new revision, so it
   syncs to all devices like any other change). Retention: at least `KPS_KEEP_REVISIONS` revisions and
   everything younger than `KPS_KEEP_DAYS`.

## Offline

The client always opens its local cached copy and saves to it first, then tries to upload. The sync state
next to the cache is small:

```json
{ "vaultId": "…", "baseRevision": 12, "baseSha256": "…", "dirty": true, "workOffline": false }
```

- Server unreachable → the change stays in the cache, `dirty: true`; the next sync uploads it (and merges if
  needed). The vault still opens without the network.
- **Work offline** is a user switch: no network traffic at all for that vault until it is switched off.
- Because the merge is per entry, a long offline period is not a problem; only edits to the *same* entry on
  both sides compete, and the losing edit stays in history.

## Multiple users

Server accounts control who may download and upload a vault (`owner` manages members, `editor` uploads,
`reader` downloads). Opening the vault still needs the KeePass master password / key file, which the users
share outside the server. To remove someone's access to the secrets, remove the member **and** change the
master key; they keep their old copy and old master key, as with any shared password file.

Administrators manage accounts and can see and manage every vault's metadata (not its contents).

## Security notes

- Passwords hashed with scrypt (N=2^15, r=8, p=1). Unknown usernames take the same time as wrong passwords.
- Device tokens: 256-bit random, only their SHA-256 stored, sliding expiry, revocable per device, all revoked
  on password change or when an account is disabled.
- Login throttling per IP+username with exponential lockout.
- Web UI: strict CSP (`default-src 'self'`), no inline script, DOM built with `textContent` only.
- Blobs are content-addressed, written atomically (temp file + fsync + rename) and checked against their
  hash on every read.
