# Clients

## KeePassXC: works today through Remote Sync

KeePassXC 2.8 (first in 2.8.0-beta1) has *Remote Sync*: it runs a download command, merges the downloaded database into the
open one in both directions (`Merger`), saves, and runs an upload command. The `kps` CLI provides both
commands. `remote-put` uploads on top of exactly the revision `remote-get` fetched, so if another device
uploads in between, the sync fails ("Run Remote Sync again") instead of overwriting.

The local `.kdbx` that KeePassXC opens is the offline copy: work normally without a network and run Remote
Sync when online.

1. Once: `npm run install-kps` (creates `~/.kps/bin/kps` with absolute paths), then
   `~/.kps/bin/kps login https://vault.example.com alice` (stores a device token in `~/.kps`).
2. Upload the database once: `kps create Family --from ~/Family.kdbx` and note the vault id. Or create the vault in
   the web UI and upload the file there.
3. KeePassXC → *Database → Database Settings → Remote Sync* → add:
   - Download command: `/Users/<you>/.kps/bin/kps remote-get <vault-id> {TEMP_DATABASE}`
   - Upload command: `/Users/<you>/.kps/bin/kps remote-put <vault-id> {TEMP_DATABASE}`

   Use the absolute path: KeePassXC does not run the commands through your shell profile.
4. *Database → Remote Sync…* after making changes, or when starting work.

### Native integration in KeePassXC (later)

| Where | What |
|---|---|
| `src/gui/remote/` | `KpsRemote` using `QNetworkAccessManager`: the protocol in `docs/PROTOCOL.md`, no external process |
| `src/gui/wizard/NewDatabaseWizard*` | Extra page *Storage: Local file / KeePass Server* with URL, username, password and **Test connection**, then choose an existing vault or create one |
| `DatabaseWidget::syncWithRemote` | Already merges both ways; use `If-Match` and on `412` download and merge again instead of failing |
| `Database::saved` signal | Push automatically after each save when online; long-poll `/wait` to sync when another device uploads |
| Status bar | Synced / pending upload / offline / conflict copies available |

## KeePassDX (fork): native integration

Implemented on the fork's `feature/keepass-server-sync` branch (see its FORK.md). The design:

The fork already has the right structure in `database/sync/RemoteDatabaseFile.kt` and
`database/action/SaveDatabaseRunnable.kt#mergeExternalChanges`: download the current remote, compare it with
`database.syncedContentHash`, merge with `DatabaseKDBXMerger` if it changed, write, verify. For the server, the
same steps go over HTTP, `syncedContentHash` becomes the server revision, and the "verify" step is the
server's `If-Match` check, which is atomic.

### 1. Server account and connection test

- `database/sync/kps/KpsClient.kt`: `HttpURLConnection` (no new dependency) for `status`, `login`, `me`,
  `listVaults`, `createVault`, `download(ifNoneMatch)`, `upload(ifMatch, sha256)`, `uploadConflict`, `wait`.
- `KpsAccountStore`: server URL, username and device token. The token goes in `EncryptedSharedPreferences`
  (or the Keystore helper the app already uses for biometric unlock). The account password is never stored.
- `FileDatabaseSelectActivity`: new **Connect to KeePass Server** button next to *Create* / *Open*.
  `KpsConnectDialog`: URL, username, password, **Test connection** (shows *Server not reachable* / *Not a
  keepass-server* / *Wrong username or password* / *Connected as alice*), then a list of vaults to open.

### 2. Create a new database on the server

In the existing create flow (`createNewFile()` → `AssignMainCredentialDialog` →
`mDatabaseViewModel.createDatabase(uri, credential)`), add a choice **Save to: this device / KeePass Server**.
For the server: test the connection, `POST /vaults { name }`, create the database in the local cache file,
then upload it with `If-Match: "0"`.

### 3. Open, save and offline using a local cache

- A server vault is represented as a URI `kps://<account-id>/<vault-id>` in the recent files list, so
  history, biometric unlock, key file and default database settings keep working unchanged.
- `filesDir/kps/<vault-id>/vault.kdbx` plus `state.json` `{ baseRevision, baseSha256, dirty, workOffline }`.
- `LoadDatabaseRunnable`: for `kps://`, try `GET content If-None-Match: baseRevision` with a short timeout,
  then always open the cache. When the server is unreachable, open from the cache and show *Offline*.
- `SaveDatabaseRunnable`: write the cache, set `dirty`, then `PUT If-Match: baseRevision`.
  On `412`, download the newer revision, run the existing `database.mergeData(...)`, write again and retry.
  This is the `mergeExternalChanges` path with the hash comparison replaced by the revision.
  If the remote has a different master key, upload the local file as a conflict copy, show the existing
  *Reconnect / reload* dialog, and continue with the server version.
- **Work offline** toggle in the database menu (writes `workOffline`), and a sync status indicator in the toolbar.
- `WorkManager` job with a `CONNECTED` constraint uploads `dirty` caches in the background. That needs no
  master key. If the upload hits `412` while the database is locked, the merge has to wait for the next unlock:
  show a notification "Changes waiting to be merged".
- While the database is open, long-poll `/wait` and offer the existing *Merge / Reload* dialog (or merge
  silently when there are no local changes).

### Alternative without changing the app: a DocumentsProvider

A small separate Android app could expose server vaults through the Storage Access Framework. Any KeePass app
(official KeePassDX, Keepass2Android) could then open them, and the fork's safe sync merges before each save.
Offline edits would only be detected as a conflict at upload, after the app has closed the file, so the
provider could only store a conflict copy instead of merging. The native integration above is better. The
provider is useful only to support unmodified apps.
