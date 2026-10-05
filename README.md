# keepass-server

Self-hosted sync server for KeePass `.kdbx` databases.

- **Zero knowledge**: the server stores the encrypted `.kdbx` files as they are and never sees a master password.
- **Multiple users and groups**: share a vault with users or whole groups as `owner`, `editor` or `reader`.
- **Conflict safe**: every upload states the revision it is based on. A stale upload is refused (`412`); the
  client merges the newer version with the KeePass merge (per entry) and uploads again. Nothing is overwritten.
- **Offline first**: clients work on a local copy, can *work offline* on purpose, and sync when back online.
- **History**: every upload is a revision that can be downloaded or restored; un-mergeable changes are kept as
  **conflict copies** (similar to Joplin's conflict notebook).
- **Live updates**: long-poll endpoint so clients sync as soon as another device uploads.
- Web UI for users, groups, vault sharing, revisions and conflict copies.
- No native dependencies: Node.js 24 with built-in SQLite.

Read [docs/DESIGN.md](docs/DESIGN.md) for how and why, [docs/PROTOCOL.md](docs/PROTOCOL.md) for the API and the
client sync algorithm, and [docs/CLIENTS.md](docs/CLIENTS.md) for KeePassXC and KeePassDX.

## Quick start

```bash
npm install
cp .env.example .env   # set KPS_ADMIN_USERNAME / KPS_ADMIN_PASSWORD
set -a; source .env; set +a
npm start              # http://localhost:8787
```

Or with Docker:

```bash
cp .env.example .env
docker compose up -d
```

Always put it behind TLS (Caddy, Traefik, nginx) or set `KPS_TLS_CERT` / `KPS_TLS_KEY`. Even though the
databases are encrypted, account passwords and tokens travel in the requests.

## Users

```bash
node src/main.ts user add alice            # prompts for the password (or KPS_PASSWORD)
node src/main.ts user add bob --admin
node src/main.ts user passwd alice
node src/main.ts user list
```

Or in the web UI under *Users* (administrators).

## Groups

Put users in groups and share a vault with a whole group; every member gets the group's role (the highest of
their own role and their groups' roles counts).

```bash
node src/main.ts group add family alice bob   # create a group with members
node src/main.ts group add-member family carol
node src/main.ts group remove-member family bob
node src/main.ts group list
node src/main.ts group delete family
```

Or in the web UI: *Groups* (administrators) to manage groups, and the *Groups* section on a vault page (owners)
to give a group `owner`, `editor` or `reader` access. A new vault can be shared with a group right away.

## Reference client `kps`

`client/` is a small TypeScript client (with [kdbxweb](https://github.com/keeweb/kdbxweb) for merging) that
implements the full offline sync algorithm. It is used by the tests and works as a CLI:

```bash
npm run kps -- test https://vault.example.com alice     # connect & test
npm run kps -- login https://vault.example.com alice
npm run kps -- create Family --from ~/Family.kdbx        # or without --from: new empty database
npm run kps -- create Family --group family:editor     # share with a group right away
npm run kps -- share <vault-id> work reader             # or later; kps unshare <vault-id> work
npm run kps -- groups
npm run kps -- vaults
npm run kps -- clone <vault-id>
npm run kps -- offline <vault-id> on                     # work offline
npm run kps -- add <vault-id> "Netflix"
npm run kps -- offline <vault-id> off
npm run kps -- sync                                      # merges with whatever changed meanwhile
npm run kps -- watch <vault-id>                          # keep syncing on every server change
```

## Configuration

| Variable | Default | |
|---|---|---|
| `KPS_HOST` / `KPS_PORT` | `0.0.0.0` / `8787` | |
| `KPS_DATA_DIR` | `./data` | SQLite database + `blobs/` |
| `KPS_ADMIN_USERNAME` / `KPS_ADMIN_PASSWORD` | | First administrator, created only when there are no users |
| `KPS_MAX_UPLOAD_MB` | `50` | |
| `KPS_KEEP_REVISIONS` | `50` | Always keep this many recent revisions per vault … |
| `KPS_KEEP_DAYS` | `30` | … and every revision younger than this |
| `KPS_TOKEN_TTL_DAYS` | `365` | Device sessions expire after this many days without use |
| `KPS_TRUST_PROXY` | `false` | Use `X-Forwarded-For` for login throttling |
| `KPS_TLS_CERT` / `KPS_TLS_KEY` | | Serve HTTPS directly |

## Backups

Back up `KPS_DATA_DIR` (stop the server, or use `sqlite3 keepass-server.sqlite ".backup …"` together with
`blobs/`). Every client also keeps a full copy of each vault it syncs.

## Development

```bash
npm test        # server + end-to-end sync tests (two simulated devices, offline, conflicts)
npm run lint    # tsc --noEmit
npm run dev     # restart on change
```
