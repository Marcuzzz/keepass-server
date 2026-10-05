import fs from 'node:fs/promises';
import path from 'node:path';
import { ApiError, type KpsApi, OfflineError } from './api.ts';
import { isInvalidKey, type Kdbx, kdbxweb, loadKdbx, saveKdbx } from './kdbx.ts';

/**
 * Everything a client keeps next to its cached copy of a vault. This is the whole offline model:
 * the cache is always the database the user works on; `dirty` says it has changes the server
 * has not seen yet; `baseRevision` is the server revision those changes were made on top of.
 */
export interface SyncState {
  serverUrl: string;
  vaultId: string;
  vaultName: string;
  baseRevision: number;
  baseSha256: string | null;
  dirty: boolean;
  /** User chose "Work offline": never contact the server until switched off. */
  workOffline: boolean;
  /** kdbxweb edit tombstones for correct history/deletion merging, kept until the next successful push. */
  editState?: kdbxweb.KdbxEditState;
  lastSyncAt?: string;
  lastError?: string;
}

export type SyncStatus =
  | 'up-to-date' // nothing to do
  | 'pulled' // took newer server version, no local changes
  | 'pushed' // uploaded local changes
  | 'merged' // server changed too: merged both and uploaded the result
  | 'offline' // server unreachable, local changes kept for later
  | 'work-offline' // sync disabled by the user
  | 'read-only' // local changes but the user may not write this vault
  | 'key-changed'; // server copy has a different master key; local copy kept as a conflict copy

export interface SyncResult {
  status: SyncStatus;
  revision: number;
  message?: string;
  conflictId?: string;
  /** The database after sync (reloaded or merged); undefined when the key changed. */
  db?: Kdbx;
}

const MAX_ATTEMPTS = 5;

export class LocalVault {
  readonly dir: string;
  state: SyncState;

  private constructor(dir: string, state: SyncState) {
    this.dir = dir;
    this.state = state;
  }

  get file(): string {
    return path.join(this.dir, 'vault.kdbx');
  }

  static async create(dir: string, state: Omit<SyncState, 'baseRevision' | 'baseSha256' | 'dirty' | 'workOffline'>): Promise<LocalVault> {
    await fs.mkdir(dir, { recursive: true });
    const vault = new LocalVault(dir, { ...state, baseRevision: 0, baseSha256: null, dirty: false, workOffline: false });
    await vault.persist();
    return vault;
  }

  static async load(dir: string): Promise<LocalVault> {
    const state = JSON.parse(await fs.readFile(path.join(dir, 'state.json'), 'utf8')) as SyncState;
    return new LocalVault(dir, state);
  }

  async hasLocalCopy(): Promise<boolean> {
    return fs.access(this.file).then(() => true, () => false);
  }

  /** Opens the cached copy. Works without any network. */
  async open(creds: kdbxweb.Credentials): Promise<Kdbx> {
    const db = await loadKdbx(await fs.readFile(this.file), creds);
    if (this.state.dirty && this.state.editState) db.setLocalEditState(this.state.editState);
    return db;
  }

  /** Saves locally and marks the vault as having unsynced changes. Never touches the network. */
  async save(db: Kdbx): Promise<void> {
    const data = await saveKdbx(db);
    this.state.editState = db.getLocalEditState();
    this.state.dirty = true;
    await this.writeFile(this.file, data);
    await this.persist();
  }

  async setWorkOffline(workOffline: boolean): Promise<void> {
    this.state.workOffline = workOffline;
    await this.persist();
  }

  /**
   * Brings the cache and the server in line:
   * - no local changes: download if the server has a newer revision (If-None-Match);
   * - local changes: upload with If-Match = baseRevision; on 412 download the newer revision,
   *   merge it into the local database (KeePass merge, per entry by UUID and modification time)
   *   and try again. Network failures leave everything as is, so the next sync resumes.
   */
  async sync(api: KpsApi, creds: kdbxweb.Credentials, openDb?: Kdbx): Promise<SyncResult> {
    if (this.state.workOffline) return { status: 'work-offline', revision: this.state.baseRevision, db: openDb };
    try {
      const result = this.state.dirty ? await this.push(api, creds, openDb) : await this.pull(api, creds, openDb);
      this.state.lastSyncAt = new Date().toISOString();
      this.state.lastError = undefined;
      await this.persist();
      return result;
    } catch (err) {
      if (err instanceof OfflineError) {
        this.state.lastError = err.message;
        await this.persist();
        return { status: 'offline', revision: this.state.baseRevision, message: err.message, db: openDb };
      }
      throw err;
    }
  }

  private async pull(api: KpsApi, creds: kdbxweb.Credentials, openDb?: Kdbx): Promise<SyncResult> {
    const known = (await this.hasLocalCopy()) ? this.state.baseRevision : undefined;
    let download;
    try {
      download = await api.download(this.state.vaultId, known || undefined);
    } catch (err) {
      if (err instanceof ApiError && err.code === 'empty_vault') return { status: 'up-to-date', revision: 0, db: openDb };
      throw err;
    }
    if (!download) return { status: 'up-to-date', revision: this.state.baseRevision, db: openDb };
    let db: Kdbx;
    try {
      db = await loadKdbx(download.data, creds);
    } catch (err) {
      if (!isInvalidKey(err)) throw err;
      await this.adoptRemote(download.revision, download.sha256, download.data);
      return { status: 'key-changed', revision: download.revision, message: 'The master key was changed on another device; unlock again with the new key' };
    }
    await this.adoptRemote(download.revision, download.sha256, download.data);
    return { status: 'pulled', revision: download.revision, db };
  }

  private async push(api: KpsApi, creds: kdbxweb.Credentials, openDb?: Kdbx): Promise<SyncResult> {
    let merged = false;
    let db = openDb;
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      const data = await fs.readFile(this.file);
      try {
        const up = await api.upload(this.state.vaultId, data, this.state.baseRevision);
        this.state.baseRevision = up.revision;
        this.state.baseSha256 = up.sha256;
        this.state.dirty = false;
        this.state.editState = undefined;
        db?.removeLocalEditState();
        return { status: merged ? 'merged' : 'pushed', revision: up.revision, db };
      } catch (err) {
        if (!(err instanceof ApiError)) throw err;
        if (err.status === 403) {
          return { status: 'read-only', revision: this.state.baseRevision, message: err.message, db };
        }
        if (err.status !== 412) throw err;
      }

      // Someone else uploaded first: merge their version into ours.
      const remote = await api.download(this.state.vaultId);
      if (!remote) throw new Error('Server reported a conflict but returned no content');
      let remoteDb: Kdbx;
      try {
        remoteDb = await loadKdbx(remote.data, creds);
      } catch (err) {
        if (!isInvalidKey(err)) throw err;
        // Cannot merge across different master keys. Keep ours as a conflict copy (on the server
        // and locally), and continue with the server's version.
        const conflictId = await api.uploadConflict(this.state.vaultId, data, this.state.baseRevision, 'Master key changed on server; local changes could not be merged');
        await this.writeFile(path.join(this.dir, `conflict-${new Date().toISOString().replace(/[:.]/g, '-')}.kdbx`), data);
        await this.adoptRemote(remote.revision, remote.sha256, remote.data);
        return {
          status: 'key-changed',
          revision: remote.revision,
          conflictId,
          message: 'The master key was changed on another device. Your unsynced changes were saved as a conflict copy.',
        };
      }
      db ??= await this.open(creds);
      db.merge(remoteDb);
      this.state.baseRevision = remote.revision;
      this.state.baseSha256 = remote.sha256;
      await this.save(db);
      merged = true;
    }
    throw new Error(`Gave up after ${MAX_ATTEMPTS} conflicting uploads; try again`);
  }

  private async adoptRemote(revision: number, sha256: string, data: Uint8Array): Promise<void> {
    await this.writeFile(this.file, data);
    this.state.baseRevision = revision;
    this.state.baseSha256 = sha256;
    this.state.dirty = false;
    this.state.editState = undefined;
  }

  private async writeFile(file: string, data: Uint8Array): Promise<void> {
    const tmp = `${file}.tmp`;
    await fs.writeFile(tmp, data);
    await fs.rename(tmp, file);
  }

  private async persist(): Promise<void> {
    await this.writeFile(path.join(this.dir, 'state.json'), new TextEncoder().encode(JSON.stringify(this.state, null, 2)));
  }
}
