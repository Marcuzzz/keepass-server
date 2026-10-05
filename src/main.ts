#!/usr/bin/env -S node --disable-warning=ExperimentalWarning
import { parseArgs } from 'node:util';
import readline from 'node:readline/promises';
import { hashPassword, validatePassword, validateUsername } from './auth.ts';
import { loadConfig } from './config.ts';
import { now, openDatabase, transaction } from './db.ts';
import { createKeepassServer } from './server.ts';

const USAGE = `Usage:
  kps-server serve                         Start the server (default)
  kps-server user add <name> [--admin]     Create a user (password from KPS_PASSWORD or prompt)
  kps-server user passwd <name>            Set a user's password and revoke their sessions
  kps-server user list                     List users
  kps-server group add <name> [<user>...]  Create a group, optionally with members
  kps-server group delete <name>           Delete a group (its vault access goes with it)
  kps-server group add-member <group> <user>
  kps-server group remove-member <group> <user>
  kps-server group list                    List groups and their members

Configuration is read from KPS_* environment variables, see .env.example.`;

async function readPassword(): Promise<string> {
  if (process.env.KPS_PASSWORD) return process.env.KPS_PASSWORD;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    return await rl.question('Password: ');
  } finally {
    rl.close();
  }
}

async function userCommand(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({ args, options: { admin: { type: 'boolean' } }, allowPositionals: true });
  const [action, name] = positionals;
  const db = openDatabase(loadConfig().dataDir);
  try {
    if (action === 'list') {
      const rows = db.prepare('SELECT username, is_admin, disabled FROM users ORDER BY username').all() as Array<{ username: string; is_admin: number; disabled: number }>;
      for (const r of rows) process.stdout.write(`${r.username}${r.is_admin ? ' (admin)' : ''}${r.disabled ? ' [disabled]' : ''}\n`);
      return;
    }
    if (!name) throw new Error(USAGE);
    const username = validateUsername(name);
    const password = validatePassword(await readPassword());
    const hash = await hashPassword(password);
    if (action === 'add') {
      db.prepare('INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)').run(username, hash, values.admin ? 1 : 0, now());
      process.stdout.write(`Created user ${username}${values.admin ? ' (admin)' : ''}\n`);
    } else if (action === 'passwd') {
      const user = db.prepare('SELECT id FROM users WHERE username = ?').get(username) as { id: number } | undefined;
      if (!user) throw new Error(`No such user: ${username}`);
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id);
      db.prepare('DELETE FROM tokens WHERE user_id = ?').run(user.id);
      process.stdout.write(`Password changed for ${username}; existing sessions revoked\n`);
    } else {
      throw new Error(USAGE);
    }
  } finally {
    db.close();
  }
}

async function groupCommand(args: string[]): Promise<void> {
  const [action, name, ...users] = args;
  const db = openDatabase(loadConfig().dataDir);
  try {
    if (action === 'list') {
      const rows = db.prepare(`
        SELECT g.name, GROUP_CONCAT(u.username, ', ') AS members FROM groups g
        LEFT JOIN group_members gm ON gm.group_id = g.id LEFT JOIN users u ON u.id = gm.user_id
        GROUP BY g.id ORDER BY g.name COLLATE NOCASE
      `).all() as Array<{ name: string; members: string | null }>;
      for (const r of rows) process.stdout.write(`${r.name}: ${r.members ?? '(no members)'}\n`);
      return;
    }
    if (!name) throw new Error(USAGE);
    const userId = (username: string): number => {
      const row = db.prepare('SELECT id FROM users WHERE username = ?').get(username) as { id: number } | undefined;
      if (!row) throw new Error(`No such user: ${username}`);
      return row.id;
    };
    const groupId = (): number => {
      const row = db.prepare('SELECT id FROM groups WHERE name = ?').get(name) as { id: number } | undefined;
      if (!row) throw new Error(`No such group: ${name}`);
      return row.id;
    };
    if (action === 'add') {
      const memberIds = users.map(userId);
      transaction(db, () => {
        const id = Number(db.prepare('INSERT INTO groups (name, created_at) VALUES (?, ?)').run(name, now()).lastInsertRowid);
        for (const uid of memberIds) db.prepare('INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)').run(id, uid);
      });
      process.stdout.write(`Created group ${name}${users.length ? ` with ${users.join(', ')}` : ''}\n`);
    } else if (action === 'delete') {
      db.prepare('DELETE FROM groups WHERE id = ?').run(groupId());
      process.stdout.write(`Deleted group ${name}\n`);
    } else if (action === 'add-member' && users.length === 1) {
      db.prepare('INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)').run(groupId(), userId(users[0]!));
      process.stdout.write(`Added ${users[0]} to ${name}\n`);
    } else if (action === 'remove-member' && users.length === 1) {
      db.prepare('DELETE FROM group_members WHERE group_id = ? AND user_id = ?').run(groupId(), userId(users[0]!));
      process.stdout.write(`Removed ${users[0]} from ${name}\n`);
    } else {
      throw new Error(USAGE);
    }
  } finally {
    db.close();
  }
}

async function serve(): Promise<void> {
  const config = loadConfig();
  const log = (line: string) => process.stdout.write(`${new Date().toISOString()} ${line}\n`);
  const app = await createKeepassServer(config, { log });
  const { port } = await app.listen();
  const { n } = app.db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number };
  log(`keepass-server listening on ${config.tls ? 'https' : 'http'}://${config.host}:${port} (data: ${config.dataDir})`);
  if (n === 0) log('No users yet: set KPS_ADMIN_USERNAME/KPS_ADMIN_PASSWORD or run "kps-server user add <name> --admin"');
  if (!config.tls) log('Serving plain HTTP: put a TLS reverse proxy in front of it for anything but localhost');
  const shutdown = () => void app.close().then(() => process.exit(0));
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

const [command = 'serve', ...rest] = process.argv.slice(2);
try {
  if (command === 'serve') await serve();
  else if (command === 'user') await userCommand(rest);
  else if (command === 'group') await groupCommand(rest);
  else throw new Error(USAGE);
} catch (err) {
  process.stderr.write(`${(err as Error).message}\n`);
  process.exit(1);
}
