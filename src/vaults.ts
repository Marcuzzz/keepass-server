import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import type { AuthUser } from './auth.ts';
import type { Config } from './config.ts';
import { type Db, now, transaction } from './db.ts';
import { HttpError } from './http.ts';
import { inspectKdbx } from './kdbx.ts';
import { BlobStore } from './storage.ts';

export type Role = 'owner' | 'editor' | 'reader';
const ROLE_RANK: Record<Role, number> = { reader: 1, editor: 2, owner: 3 };
const RANK_ROLE: Record<number, Role> = { 1: 'reader', 2: 'editor', 3: 'owner' };

/** Every (vault_id, role) the user gets directly or through a group; bind the user id twice. */
const USER_ROLES_SQL = `
  SELECT vault_id, role FROM vault_members WHERE user_id = ?
  UNION ALL
  SELECT vg.vault_id, vg.role FROM vault_groups vg JOIN group_members gm ON gm.group_id = vg.group_id WHERE gm.user_id = ?
`;
const DAY = 24 * 60 * 60 * 1000;

export interface VaultRow {
  id: string;
  name: string;
  created_at: number;
  current_rev: number;
}

export interface RevisionRow {
  rev: number;
  sha256: string;
  size: number;
  created_at: number;
  username: string | null;
  device_name: string | null;
  base_rev: number | null;
  note: string | null;
}

export interface CommitResult {
  revision: number;
  sha256: string;
  /** True when the upload was identical to the current revision (e.g. a retried request). */
  unchanged: boolean;
}

export interface CommitOptions {
  /** Revisions the client based its upload on (If-Match). '*' overwrites unconditionally. */
  ifMatch: Array<number | '*'>;
  note?: string;
  /** Verifies the upload arrived intact (X-KPS-SHA256). */
  expectedSha256?: string;
}

export class VaultService {
  readonly events = new EventEmitter();
  /** Blobs referenced by an upload in progress; garbage collection must not remove them. */
  private readonly pending = new Map<string, number>();

  private readonly db: Db;
  readonly blobs: BlobStore;
  private readonly config: Config;

  constructor(db: Db, blobs: BlobStore, config: Config) {
    this.db = db;
    this.blobs = blobs;
    this.config = config;
    this.events.setMaxListeners(0);
  }

  /** Returns the vault and caller's role, or 404 so callers can't probe for other vaults. */
  access(vaultId: string, user: AuthUser, minRole: Role = 'reader'): { vault: VaultRow; role: Role } {
    const vault = this.db.prepare('SELECT id, name, created_at, current_rev FROM vaults WHERE id = ?').get(vaultId) as
      | VaultRow
      | undefined;
    // Administrators are owners of every vault, also where a membership or group gives them a lower role.
    const role = vault ? (user.isAdmin ? 'owner' : this.effectiveRole(vaultId, user.id)) : undefined;
    if (!vault || !role) throw new HttpError(404, 'vault_not_found', 'Vault not found');
    if (ROLE_RANK[role] < ROLE_RANK[minRole]) {
      throw new HttpError(403, 'forbidden', `Requires ${minRole} access to this vault`);
    }
    return { vault, role };
  }

  /** Highest role the user has on the vault, directly or through any of their groups. */
  effectiveRole(vaultId: string, userId: number): Role | undefined {
    const rows = this.db.prepare(`SELECT role FROM (${USER_ROLES_SQL}) WHERE vault_id = ?`).all(userId, userId, vaultId) as Array<{ role: Role }>;
    const rank = Math.max(0, ...rows.map((r) => ROLE_RANK[r.role]));
    return RANK_ROLE[rank];
  }

  list(user: AuthUser): Array<Record<string, unknown>> {
    const rows = this.db.prepare(`
      WITH best AS (
        SELECT vault_id, MAX(CASE role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END) AS rank
        FROM (${USER_ROLES_SQL}) GROUP BY vault_id
      )
      SELECT v.id, v.name, v.created_at, v.current_rev, b.rank, r.sha256, r.size, r.created_at AS updated_at
      FROM vaults v
      LEFT JOIN best b ON b.vault_id = v.id
      LEFT JOIN revisions r ON r.vault_id = v.id AND r.rev = v.current_rev
      WHERE b.rank IS NOT NULL OR ?
      ORDER BY v.name COLLATE NOCASE
    `).all(user.id, user.id, user.isAdmin ? 1 : 0) as unknown as Array<VaultRow & { rank: number | null; sha256: string | null; size: number | null; updated_at: number | null }>;
    return rows.map((r) => this.describe(r, user.isAdmin || !r.rank ? 'owner' : RANK_ROLE[r.rank]!, r));
  }

  describe(vault: VaultRow, role: Role, current?: { sha256: string | null; size: number | null; updated_at: number | null }): Record<string, unknown> {
    const head = current ?? this.currentRevision(vault.id, vault.current_rev);
    const conflicts = (this.db.prepare('SELECT COUNT(*) AS n FROM conflicts WHERE vault_id = ?').get(vault.id) as { n: number }).n;
    return {
      id: vault.id,
      name: vault.name,
      role,
      revision: vault.current_rev,
      sha256: head?.sha256 ?? null,
      size: head?.size ?? null,
      createdAt: new Date(vault.created_at).toISOString(),
      updatedAt: head?.updated_at ? new Date(head.updated_at).toISOString() : null,
      conflicts,
    };
  }

  private currentRevision(vaultId: string, rev: number): { sha256: string; size: number; updated_at: number } | undefined {
    return this.db.prepare('SELECT sha256, size, created_at AS updated_at FROM revisions WHERE vault_id = ? AND rev = ?').get(vaultId, rev) as
      | { sha256: string; size: number; updated_at: number }
      | undefined;
  }

  create(user: AuthUser, name: string, groups: Array<{ groupId: number; role: Role }> = []): VaultRow {
    const vault: VaultRow = { id: crypto.randomUUID(), name, created_at: now(), current_rev: 0 };
    transaction(this.db, () => {
      this.db.prepare('INSERT INTO vaults (id, name, created_by, created_at, current_rev) VALUES (?, ?, ?, ?, 0)').run(
        vault.id, name, user.id, vault.created_at,
      );
      this.db.prepare("INSERT INTO vault_members (vault_id, user_id, role) VALUES (?, ?, 'owner')").run(vault.id, user.id);
      const share = this.db.prepare('INSERT OR REPLACE INTO vault_groups (vault_id, group_id, role) VALUES (?, ?, ?)');
      for (const g of groups) share.run(vault.id, g.groupId, g.role);
    });
    return vault;
  }

  /**
   * New vault owned by `user` whose revision 1 is the source's current database (an empty source gives an
   * empty copy). The blob is shared, not copied. History and conflict copies stay with the source;
   * `copySharing` also copies its members and group roles.
   */
  duplicate(sourceId: string, user: AuthUser, name: string, copySharing: boolean): VaultRow {
    const vault: VaultRow = { id: crypto.randomUUID(), name, created_at: now(), current_rev: 0 };
    transaction(this.db, () => {
      const source = this.db.prepare('SELECT name, current_rev FROM vaults WHERE id = ?').get(sourceId) as { name: string; current_rev: number } | undefined;
      if (!source) throw new HttpError(404, 'vault_not_found', 'Vault not found');
      const head = this.currentRevision(sourceId, source.current_rev);
      vault.current_rev = head ? 1 : 0;
      this.db.prepare('INSERT INTO vaults (id, name, created_by, created_at, current_rev) VALUES (?, ?, ?, ?, ?)').run(
        vault.id, name, user.id, vault.created_at, vault.current_rev,
      );
      this.db.prepare("INSERT INTO vault_members (vault_id, user_id, role) VALUES (?, ?, 'owner')").run(vault.id, user.id);
      if (copySharing) {
        this.db.prepare('INSERT OR IGNORE INTO vault_members (vault_id, user_id, role) SELECT ?, user_id, role FROM vault_members WHERE vault_id = ?')
          .run(vault.id, sourceId);
        this.db.prepare('INSERT INTO vault_groups (vault_id, group_id, role) SELECT ?, group_id, role FROM vault_groups WHERE vault_id = ?')
          .run(vault.id, sourceId);
      }
      if (head) {
        this.db.prepare(`
          INSERT INTO revisions (vault_id, rev, sha256, size, created_at, user_id, device_name, base_rev, note)
          VALUES (?, 1, ?, ?, ?, ?, ?, NULL, ?)
        `).run(vault.id, head.sha256, head.size, vault.created_at, user.id, user.deviceName,
          `Copy of "${source.name}" revision ${source.current_rev}`.slice(0, 500));
      }
    });
    return vault;
  }

  rename(vaultId: string, name: string): void {
    this.db.prepare('UPDATE vaults SET name = ? WHERE id = ?').run(name, vaultId);
  }

  async remove(vaultId: string): Promise<void> {
    const shas = this.blobRefs(vaultId);
    this.db.prepare('DELETE FROM vaults WHERE id = ?').run(vaultId);
    await this.collect(shas);
    this.events.emit(vaultId, -1);
  }

  async readRevision(vaultId: string, rev: number): Promise<{ data: Buffer; row: { sha256: string; size: number } }> {
    const row = this.db.prepare('SELECT sha256, size FROM revisions WHERE vault_id = ? AND rev = ?').get(vaultId, rev) as
      | { sha256: string; size: number }
      | undefined;
    if (!row) throw new HttpError(404, 'revision_not_found', `Revision ${rev} not found (it may have been pruned)`);
    return { data: await this.blobs.get(row.sha256), row };
  }

  revisions(vaultId: string): RevisionRow[] {
    return this.db.prepare(`
      SELECT r.rev, r.sha256, r.size, r.created_at, u.username, r.device_name, r.base_rev, r.note
      FROM revisions r LEFT JOIN users u ON u.id = r.user_id
      WHERE r.vault_id = ? ORDER BY r.rev DESC
    `).all(vaultId) as unknown as RevisionRow[];
  }

  /**
   * Stores a new revision if the client's base revision is still current (optimistic concurrency).
   * The blob is written first; the check-and-insert below is synchronous, so two uploads can never
   * both succeed against the same base revision.
   */
  async commit(vaultId: string, user: AuthUser, data: Buffer, opts: CommitOptions): Promise<CommitResult> {
    if (!inspectKdbx(data)) {
      throw new HttpError(422, 'invalid_kdbx', 'Upload is not a KeePass 2.x (KDBX 3/4) database');
    }
    const sha = BlobStore.sha256(data);
    if (opts.expectedSha256 && opts.expectedSha256.toLowerCase() !== sha) {
      throw new HttpError(400, 'checksum_mismatch', 'Upload does not match X-KPS-SHA256; it was probably truncated');
    }
    this.pin(sha);
    try {
      await this.blobs.put(data);
      const result = transaction(this.db, (): CommitResult => {
        const vault = this.db.prepare('SELECT current_rev FROM vaults WHERE id = ?').get(vaultId) as { current_rev: number } | undefined;
        if (!vault) throw new HttpError(404, 'vault_not_found', 'Vault not found');
        const current = vault.current_rev;
        const head = this.currentRevision(vaultId, current);
        if (head && head.sha256 === sha) {
          // Same bytes as the head: a retried upload whose response got lost, or a no-op save.
          return { revision: current, sha256: sha, unchanged: true };
        }
        const force = opts.ifMatch.includes('*');
        if (!force && !opts.ifMatch.includes(current)) {
          throw new HttpError(412, 'conflict', 'The vault changed on the server. Download it, merge and upload again.', {
            currentRevision: current,
            currentSha256: head?.sha256 ?? null,
          });
        }
        const rev = current + 1;
        const baseRev = force ? current : (opts.ifMatch[0] as number);
        this.db.prepare(`
          INSERT INTO revisions (vault_id, rev, sha256, size, created_at, user_id, device_name, base_rev, note)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(vaultId, rev, sha, data.length, now(), user.id, user.deviceName, baseRev, opts.note ?? null);
        this.db.prepare('UPDATE vaults SET current_rev = ? WHERE id = ?').run(rev, vaultId);
        return { revision: rev, sha256: sha, unchanged: false };
      });
      if (!result.unchanged) {
        this.events.emit(vaultId, result.revision);
        await this.prune(vaultId);
      }
      return result;
    } finally {
      this.unpin(sha);
      await this.collect([sha]);
    }
  }

  /** Drops revisions that are both beyond keepRevisions and older than keepDays. */
  async prune(vaultId: string): Promise<void> {
    const vault = this.db.prepare('SELECT current_rev FROM vaults WHERE id = ?').get(vaultId) as { current_rev: number } | undefined;
    if (!vault) return;
    const maxRev = vault.current_rev - this.config.keepRevisions;
    const before = now() - this.config.keepDays * DAY;
    const doomed = this.db.prepare('SELECT sha256 FROM revisions WHERE vault_id = ? AND rev <= ? AND created_at < ?').all(
      vaultId, maxRev, before,
    ) as Array<{ sha256: string }>;
    if (doomed.length === 0) return;
    this.db.prepare('DELETE FROM revisions WHERE vault_id = ? AND rev <= ? AND created_at < ?').run(vaultId, maxRev, before);
    await this.collect(doomed.map((d) => d.sha256));
  }

  // --- conflict copies --------------------------------------------------------------------------

  async addConflict(vaultId: string, user: AuthUser, data: Buffer, baseRev: number | null, reason: string | null): Promise<string> {
    if (!inspectKdbx(data)) throw new HttpError(422, 'invalid_kdbx', 'Upload is not a KeePass 2.x (KDBX 3/4) database');
    const id = crypto.randomUUID();
    const sha = BlobStore.sha256(data);
    this.pin(sha);
    try {
      await this.blobs.put(data);
      this.db.prepare(`
        INSERT INTO conflicts (id, vault_id, sha256, size, created_at, user_id, device_name, base_rev, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(id, vaultId, sha, data.length, now(), user.id, user.deviceName, baseRev, reason);
    } finally {
      this.unpin(sha);
    }
    this.events.emit(vaultId, this.access(vaultId, user).vault.current_rev);
    return id;
  }

  conflicts(vaultId: string): Array<Record<string, unknown>> {
    const rows = this.db.prepare(`
      SELECT c.id, c.sha256, c.size, c.created_at, u.username, c.device_name, c.base_rev, c.reason
      FROM conflicts c LEFT JOIN users u ON u.id = c.user_id
      WHERE c.vault_id = ? ORDER BY c.created_at DESC
    `).all(vaultId) as Array<{ id: string; sha256: string; size: number; created_at: number; username: string | null; device_name: string | null; base_rev: number | null; reason: string | null }>;
    return rows.map((r) => ({
      id: r.id, sha256: r.sha256, size: r.size, createdAt: new Date(r.created_at).toISOString(),
      username: r.username, deviceName: r.device_name, baseRevision: r.base_rev, reason: r.reason,
    }));
  }

  async readConflict(vaultId: string, conflictId: string): Promise<Buffer> {
    const row = this.db.prepare('SELECT sha256 FROM conflicts WHERE vault_id = ? AND id = ?').get(vaultId, conflictId) as
      | { sha256: string }
      | undefined;
    if (!row) throw new HttpError(404, 'conflict_not_found', 'Conflict copy not found');
    return this.blobs.get(row.sha256);
  }

  async removeConflict(vaultId: string, conflictId: string): Promise<void> {
    const row = this.db.prepare('SELECT sha256 FROM conflicts WHERE vault_id = ? AND id = ?').get(vaultId, conflictId) as
      | { sha256: string }
      | undefined;
    if (!row) throw new HttpError(404, 'conflict_not_found', 'Conflict copy not found');
    this.db.prepare('DELETE FROM conflicts WHERE id = ?').run(conflictId);
    await this.collect([row.sha256]);
  }

  // --- change notification ----------------------------------------------------------------------

  /** Resolves with the current revision as soon as it is greater than `since`, or after timeoutMs. */
  waitForChange(vaultId: string, since: number, timeoutMs: number, signal: AbortSignal): Promise<number> {
    const current = (this.db.prepare('SELECT current_rev FROM vaults WHERE id = ?').get(vaultId) as { current_rev: number }).current_rev;
    if (current !== since) return Promise.resolve(current);
    return new Promise((resolve) => {
      const done = (rev: number) => {
        clearTimeout(timer);
        this.events.off(vaultId, onChange);
        signal.removeEventListener('abort', onAbort);
        resolve(rev);
      };
      const onChange = (rev: number) => done(rev);
      const onAbort = () => done(since);
      const timer = setTimeout(() => done(since), timeoutMs);
      this.events.on(vaultId, onChange);
      signal.addEventListener('abort', onAbort);
    });
  }

  // --- blob garbage collection ------------------------------------------------------------------

  private blobRefs(vaultId: string): string[] {
    const rows = this.db.prepare(
      'SELECT sha256 FROM revisions WHERE vault_id = ? UNION SELECT sha256 FROM conflicts WHERE vault_id = ?',
    ).all(vaultId, vaultId) as Array<{ sha256: string }>;
    return rows.map((r) => r.sha256);
  }

  private pin(sha: string): void {
    this.pending.set(sha, (this.pending.get(sha) ?? 0) + 1);
  }

  private unpin(sha: string): void {
    const n = (this.pending.get(sha) ?? 1) - 1;
    if (n <= 0) this.pending.delete(sha);
    else this.pending.set(sha, n);
  }

  private async collect(shas: string[]): Promise<void> {
    const isUsed = this.db.prepare(
      'SELECT 1 FROM revisions WHERE sha256 = ? UNION ALL SELECT 1 FROM conflicts WHERE sha256 = ? LIMIT 1',
    );
    for (const sha of new Set(shas)) {
      await this.blobs.deleteIf(sha, () => !this.pending.has(sha) && !isUsed.get(sha, sha));
    }
  }
}
