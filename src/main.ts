#!/usr/bin/env -S node --disable-warning=ExperimentalWarning
import { parseArgs } from 'node:util';
import readline from 'node:readline/promises';
import { hashPassword, validatePassword, validateUsername } from './auth.ts';
import { loadConfig } from './config.ts';
import { now, openDatabase } from './db.ts';
import { createKeepassServer } from './server.ts';

const USAGE = `Usage:
  kps-server serve                         Start the server (default)
  kps-server user add <name> [--admin]     Create a user (password from KPS_PASSWORD or prompt)
  kps-server user passwd <name>            Set a user's password and revoke their sessions
  kps-server user list                     List users

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
  else throw new Error(USAGE);
} catch (err) {
  process.stderr.write(`${(err as Error).message}\n`);
  process.exit(1);
}
