import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

const MIGRATIONS: string[] = [
  `
  CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
  );

  CREATE TABLE tokens (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    device_name  TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
  );

  CREATE TABLE vaults (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    created_by   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at   INTEGER NOT NULL,
    current_rev  INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE vault_members (
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role     TEXT NOT NULL CHECK (role IN ('owner', 'editor', 'reader')),
    PRIMARY KEY (vault_id, user_id)
  );

  CREATE TABLE revisions (
    vault_id    TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    rev         INTEGER NOT NULL,
    sha256      TEXT NOT NULL,
    size        INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    device_name TEXT,
    base_rev    INTEGER,
    note        TEXT,
    PRIMARY KEY (vault_id, rev)
  );

  CREATE TABLE conflicts (
    id          TEXT PRIMARY KEY,
    vault_id    TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    sha256      TEXT NOT NULL,
    size        INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    device_name TEXT,
    base_rev    INTEGER,
    reason      TEXT
  );

  CREATE INDEX idx_tokens_user ON tokens(user_id);
  CREATE INDEX idx_members_user ON vault_members(user_id);
  CREATE INDEX idx_conflicts_vault ON conflicts(vault_id);
  `,
];

export type Db = DatabaseSync;

export function openDatabase(dataDir: string): Db {
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(path.join(dataDir, 'keepass-server.sqlite'));
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  migrate(db);
  return db;
}

function migrate(db: Db): void {
  const row = db.prepare('PRAGMA user_version').get() as { user_version: number };
  for (let v = row.user_version; v < MIGRATIONS.length; v++) {
    transaction(db, () => {
      db.exec(MIGRATIONS[v]!);
      db.exec(`PRAGMA user_version = ${v + 1}`);
    });
  }
}

/** Runs fn inside a transaction. fn must be synchronous so no other request can interleave. */
export function transaction<T>(db: Db, fn: () => T): T {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

export function now(): number {
  return Date.now();
}
