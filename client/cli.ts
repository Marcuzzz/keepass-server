#!/usr/bin/env -S node --disable-warning=ExperimentalWarning
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { parseArgs } from 'node:util';
import { ApiError, KpsApi, OfflineError, type Role } from './api.ts';
import { credentials, kdbxweb, loadKdbx } from './kdbx.ts';
import { LocalVault, type SyncResult } from './sync.ts';

const HOME = process.env.KPS_HOME ?? path.join(os.homedir(), '.kps');
const SESSION_FILE = path.join(HOME, 'session.json');

const USAGE = `kps - reference client for keepass-server

  kps test <url> <username> [--vault <id>]   Test a server connection and credentials
  kps login <url> <username> [--device <name>]
  kps logout
  kps vaults                                 List vaults on the server (and local sync state)
  kps create <name> [--from <file.kdbx>] [--group <group>:<role> ...]
                                             Create a vault: upload a file, or start a new database;
                                             --group shares it with a group (role: owner|editor|reader)
  kps rename <vault-id> <new name>           Rename a vault (owner)
  kps duplicate <vault-id> [<name>] [--with-sharing]
                                             Copy a vault (current database, same master password);
                                             --with-sharing also copies members and groups (owner)
  kps protect <vault-id> on|off              Turn deletion protection on or off (owner)
  kps delete <vault-id> [--yes]              Delete a vault and its history on the server (owner);
                                             asks for the vault name unless --yes
  kps groups                                 List your groups (administrators: all groups)
  kps share <vault-id> <group> <role>        Give a group access to a vault (owner)
  kps unshare <vault-id> <group>             Remove a group's access to a vault (owner)
  kps clone <vault-id>                       Download a vault into the local cache
  kps sync [<vault-id>]                      Sync one or all local vaults
  kps offline <vault-id> on|off              Work offline (never contact the server) or go back online
  kps entries <vault-id>                     List entry titles from the local cache (works offline)
  kps add <vault-id> <title>                 Add an entry with a generated password, then sync
  kps watch <vault-id>                       Keep syncing whenever the server has a new revision
  kps export <vault-id> <file.kdbx>          Copy the local cache to a file

  KeePassXC "Remote Sync" (Database > Database settings > Remote Sync):
  kps remote-get <vault-id> <file>           Download command:  kps remote-get <id> {TEMP_DATABASE}
  kps remote-put <vault-id> <file>           Upload command:    kps remote-put <id> {TEMP_DATABASE}

Environment: KPS_HOME (default ~/.kps), KPS_PASSWORD (account), KPS_DB_PASSWORD (master password)`;

const ROLES: Role[] = ['owner', 'editor', 'reader'];

interface Session {
  serverUrl: string;
  token: string;
  username: string;
}

function out(line = ''): void {
  process.stdout.write(`${line}\n`);
}

function ask(question: string, hidden = false): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (hidden) {
      const write = (rl as unknown as { _writeToOutput: (s: string) => void });
      write._writeToOutput = (s: string) => {
        if (s.startsWith(question)) process.stdout.write(question);
      };
    }
    rl.question(question, (answer) => {
      rl.close();
      if (hidden) process.stdout.write('\n');
      resolve(answer);
    });
  });
}

async function accountPassword(): Promise<string> {
  return process.env.KPS_PASSWORD ?? ask('Account password: ', true);
}

async function masterCredentials(): Promise<kdbxweb.Credentials> {
  return credentials(process.env.KPS_DB_PASSWORD ?? (await ask('Master password: ', true)));
}

async function loadSession(): Promise<Session> {
  try {
    return JSON.parse(await fs.readFile(SESSION_FILE, 'utf8')) as Session;
  } catch {
    throw new Error('Not logged in. Run: kps login <url> <username>');
  }
}

async function api(): Promise<KpsApi> {
  const session = await loadSession();
  return new KpsApi(session.serverUrl, session.token);
}

function vaultDir(vaultId: string): string {
  if (!/^[0-9a-f-]{36}$/.test(vaultId)) throw new Error(`Invalid vault id: ${vaultId}`);
  return path.join(HOME, 'vaults', vaultId);
}

async function localVaults(): Promise<LocalVault[]> {
  const dir = path.join(HOME, 'vaults');
  const ids = await fs.readdir(dir).catch(() => [] as string[]);
  return Promise.all(ids.map((id) => LocalVault.load(path.join(dir, id))));
}

function describe(name: string, result: SyncResult): string {
  const extra = result.message ? ` - ${result.message}` : '';
  return `${name}: ${result.status} (revision ${result.revision})${extra}`;
}

async function syncOne(client: KpsApi, vault: LocalVault, creds?: kdbxweb.Credentials): Promise<SyncResult> {
  const result = await vault.sync(client, creds ?? (await masterCredentials()));
  out(describe(vault.state.vaultName, result));
  if (result.conflictId) out(`  conflict copy ${result.conflictId} stored on the server and in ${vault.dir}`);
  return result;
}

const commands: Record<string, (args: string[]) => Promise<void>> = {
  async test(args) {
    const { values, positionals } = parseArgs({ args, options: { vault: { type: 'string' } }, allowPositionals: true });
    const [url, username] = positionals;
    if (!url || !username) throw new Error(USAGE);
    const result = await KpsApi.testConnection(url, username, await accountPassword(), values.vault);
    out(`${result.ok ? 'OK' : 'FAILED'} [${result.step}] ${result.message}`);
    if (result.vault) out(`Vault "${result.vault.name}": revision ${result.vault.revision}, role ${result.vault.role}`);
    if (!result.ok) process.exitCode = 1;
  },

  async login(args) {
    const { values, positionals } = parseArgs({ args, options: { device: { type: 'string' } }, allowPositionals: true });
    const [url, username] = positionals;
    if (!url || !username) throw new Error(USAGE);
    const client = new KpsApi(url);
    const token = await client.login(username, await accountPassword(), values.device ?? `kps on ${os.hostname()}`);
    await fs.mkdir(HOME, { recursive: true, mode: 0o700 });
    await fs.writeFile(SESSION_FILE, JSON.stringify({ serverUrl: client.baseUrl, token, username } satisfies Session), { mode: 0o600 });
    out(`Logged in to ${client.baseUrl} as ${username}`);
  },

  async logout() {
    await (await api()).logout().catch(() => undefined);
    await fs.rm(SESSION_FILE, { force: true });
    out('Logged out');
  },

  async vaults() {
    const local = new Map((await localVaults()).map((v) => [v.state.vaultId, v]));
    for (const v of await (await api()).listVaults()) {
      const l = local.get(v.id);
      const state = l ? ` local r${l.state.baseRevision}${l.state.dirty ? ' (unsynced changes)' : ''}${l.state.workOffline ? ' [offline]' : ''}` : '';
      const conflicts = v.conflicts ? `, ${v.conflicts} conflict cop${v.conflicts === 1 ? 'y' : 'ies'}` : '';
      out(`${v.id}  ${v.name}  [${v.role}] r${v.revision}${v.protected ? ' (protected)' : ''}${conflicts}${state}`);
    }
  },

  async create(args) {
    const { values, positionals } = parseArgs({
      args, options: { from: { type: 'string' }, group: { type: 'string', multiple: true } }, allowPositionals: true,
    });
    const [name] = positionals;
    if (!name) throw new Error(USAGE);
    const groups = (values.group ?? []).map((spec) => {
      const at = spec.lastIndexOf(':');
      const role = spec.slice(at + 1);
      if (at <= 0 || !ROLES.includes(role as Role)) throw new Error(`--group must look like <group>:${ROLES.join('|')}`);
      return { name: spec.slice(0, at), role: role as Role };
    });
    const client = await api();
    let db: kdbxweb.Kdbx;
    const creds = await masterCredentials();
    if (values.from) {
      db = await loadKdbx(await fs.readFile(values.from), creds); // proves the password before uploading
    } else {
      db = kdbxweb.Kdbx.create(creds, name);
    }
    const info = await client.createVault(name, groups);
    const vault = await LocalVault.create(vaultDir(info.id), { serverUrl: client.baseUrl, vaultId: info.id, vaultName: name });
    await vault.save(db);
    await syncOne(client, vault, creds);
    out(`Vault id: ${info.id}`);
  },

  async rename(args) {
    const [vaultId, ...name] = args;
    if (!vaultId || !name.length) throw new Error(USAGE);
    const info = await (await api()).renameVault(vaultId, name.join(' '));
    out(`Renamed to "${info.name}"`);
  },

  async duplicate(args) {
    const { values, positionals } = parseArgs({ args, options: { 'with-sharing': { type: 'boolean' } }, allowPositionals: true });
    const [vaultId, ...name] = positionals;
    if (!vaultId) throw new Error(USAGE);
    const info = await (await api()).duplicateVault(vaultId, name.join(' ') || undefined, values['with-sharing'] === true);
    out(`Vault "${info.name}" created, id: ${info.id}`);
  },

  async protect(args) {
    const [vaultId, mode] = args;
    if (!vaultId || (mode !== 'on' && mode !== 'off')) throw new Error(USAGE);
    const info = await (await api()).setVaultProtected(vaultId, mode === 'on');
    out(`"${info.name}" is ${info.protected ? 'protected from deletion' : 'no longer protected from deletion'}`);
  },

  async delete(args) {
    const { values, positionals } = parseArgs({ args, options: { yes: { type: 'boolean' } }, allowPositionals: true });
    const [vaultId] = positionals;
    if (!vaultId) throw new Error(USAGE);
    const client = await api();
    const info = await client.getVault(vaultId);
    if (info.protected) throw new Error(`"${info.name}" is protected from deletion; run: kps protect ${vaultId} off`);
    if (!values.yes) {
      const typed = await ask(`Delete "${info.name}" with all ${info.revision} revision(s) on the server? Type the vault name to confirm: `);
      if (typed.trim() !== info.name) throw new Error('Name did not match; nothing was deleted');
    }
    await client.deleteVault(vaultId);
    out(`Vault "${info.name}" deleted`);
    // Keep a local cache that holds changes the server never got; the user can still export them.
    const local = (await localVaults()).find((v) => v.state.vaultId === vaultId);
    if (local?.state.dirty) out(`The local copy has unsynced changes and was kept: kps export ${vaultId} <file.kdbx>`);
    else await fs.rm(vaultDir(vaultId), { recursive: true, force: true });
  },

  async groups() {
    for (const g of await (await api()).listGroups()) {
      out(`${g.name}  (${g.members.length} member${g.members.length === 1 ? '' : 's'}): ${g.members.map((m) => m.username).join(', ')}`);
    }
  },

  async share(args) {
    const [vaultId, group, role] = args;
    if (!vaultId || !group || !ROLES.includes(role as Role)) throw new Error(USAGE);
    await (await api()).shareWithGroup(vaultId, group, role as Role);
    out(`Group ${group} now has ${role} access`);
  },

  async unshare(args) {
    const [vaultId, group] = args;
    if (!vaultId || !group) throw new Error(USAGE);
    await (await api()).unshareGroup(vaultId, group);
    out(`Group ${group} no longer has access`);
  },

  async clone(args) {
    const [vaultId] = args;
    if (!vaultId) throw new Error(USAGE);
    const client = await api();
    const info = await client.getVault(vaultId);
    const vault = await LocalVault.create(vaultDir(info.id), { serverUrl: client.baseUrl, vaultId: info.id, vaultName: info.name });
    await syncOne(client, vault);
  },

  async sync(args) {
    const client = await api();
    const vaults = args[0] ? [await LocalVault.load(vaultDir(args[0]))] : await localVaults();
    const creds = await masterCredentials();
    for (const vault of vaults) await syncOne(client, vault, creds);
  },

  async offline(args) {
    const [vaultId, mode] = args;
    if (!vaultId || (mode !== 'on' && mode !== 'off')) throw new Error(USAGE);
    const vault = await LocalVault.load(vaultDir(vaultId));
    await vault.setWorkOffline(mode === 'on');
    out(`${vault.state.vaultName}: ${mode === 'on' ? 'working offline' : 'online'}`);
  },

  async entries(args) {
    const [vaultId] = args;
    if (!vaultId) throw new Error(USAGE);
    const vault = await LocalVault.load(vaultDir(vaultId));
    const db = await vault.open(await masterCredentials());
    for (const entry of db.getDefaultGroup().allEntries()) out(String(entry.fields.get('Title') ?? ''));
  },

  async add(args) {
    const [vaultId, title] = args;
    if (!vaultId || !title) throw new Error(USAGE);
    const vault = await LocalVault.load(vaultDir(vaultId));
    const creds = await masterCredentials();
    const db = await vault.open(creds);
    const entry = db.createEntry(db.getDefaultGroup());
    entry.fields.set('Title', title);
    entry.fields.set('Password', kdbxweb.ProtectedValue.fromString(crypto.randomBytes(18).toString('base64url')));
    entry.times.update();
    await vault.save(db);
    out(`Added "${title}" locally`);
    await vault.sync(await api(), creds, db).then((r) => out(describe(vault.state.vaultName, r)));
  },

  async watch(args) {
    const [vaultId] = args;
    if (!vaultId) throw new Error(USAGE);
    const client = await api();
    const vault = await LocalVault.load(vaultDir(vaultId));
    const creds = await masterCredentials();
    out(`Watching ${vault.state.vaultName} (Ctrl+C to stop)`);
    for (;;) {
      await syncOne(client, vault, creds);
      try {
        await client.waitForChange(vault.state.vaultId, vault.state.baseRevision, 25);
      } catch (err) {
        if (!(err instanceof OfflineError)) throw err;
        await new Promise((r) => setTimeout(r, 10_000));
      }
    }
  },

  async export(args) {
    const [vaultId, file] = args;
    if (!vaultId || !file) throw new Error(USAGE);
    await fs.copyFile((await LocalVault.load(vaultDir(vaultId))).file, file);
    out(`Wrote ${file}`);
  },
};

/** Revision handed to KeePassXC by remote-get; remote-put uploads on top of exactly that revision. */
function remoteStateFile(vaultId: string): string {
  return path.join(HOME, 'remote', `${path.basename(vaultDir(vaultId))}.json`);
}

commands['remote-get'] = async (args) => {
  const [vaultId, file] = args;
  if (!vaultId || !file) throw new Error(USAGE);
  const download = await (await api()).download(vaultId);
  if (!download) throw new Error('No content');
  await fs.writeFile(file, download.data);
  await fs.mkdir(path.join(HOME, 'remote'), { recursive: true, mode: 0o700 });
  await fs.writeFile(remoteStateFile(vaultId), JSON.stringify({ revision: download.revision, sha256: download.sha256 }));
  out(`Downloaded revision ${download.revision}`);
};

commands['remote-put'] = async (args) => {
  const [vaultId, file] = args;
  if (!vaultId || !file) throw new Error(USAGE);
  const { revision } = JSON.parse(await fs.readFile(remoteStateFile(vaultId), 'utf8')) as { revision: number };
  try {
    const result = await (await api()).upload(vaultId, await fs.readFile(file), revision, 'KeePassXC remote sync');
    out(result.unchanged ? `Unchanged (revision ${result.revision})` : `Uploaded revision ${result.revision}`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 412) {
      throw new Error('Another device uploaded while syncing; nothing was overwritten. Run Remote Sync again.');
    }
    throw err;
  }
};

const [command, ...rest] = process.argv.slice(2);
const handler = command ? commands[command] : undefined;
if (!handler) {
  out(USAGE);
  process.exitCode = command ? 1 : 0;
} else {
  try {
    await handler(rest);
  } catch (err) {
    const message = err instanceof ApiError ? `${err.message} (${err.status} ${err.code})` : (err as Error).message;
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  }
}
