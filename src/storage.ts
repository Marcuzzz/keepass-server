import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

const SHA256_RE = /^[0-9a-f]{64}$/;

/**
 * Content-addressed store for the encrypted .kdbx files. Identical uploads share one file.
 * Writes go to a temp file, are fsynced and then renamed, so a crash never leaves a partial blob.
 */
export class BlobStore {
  private readonly root: string;
  /** Serialises put/delete of the same blob so a delete can't race a concurrent identical upload. */
  private readonly locks = new Map<string, Promise<unknown>>();

  constructor(dataDir: string) {
    this.root = path.join(dataDir, 'blobs');
  }

  static sha256(data: Uint8Array): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  private pathFor(sha: string): string {
    if (!SHA256_RE.test(sha)) throw new Error(`Invalid blob id: ${sha}`);
    return path.join(this.root, sha.slice(0, 2), sha);
  }

  private async locked<T>(sha: string, fn: () => Promise<T>): Promise<T> {
    const previous = this.locks.get(sha) ?? Promise.resolve();
    const run = previous.catch(() => undefined).then(fn);
    this.locks.set(sha, run);
    try {
      return await run;
    } finally {
      if (this.locks.get(sha) === run) this.locks.delete(sha);
    }
  }

  put(data: Uint8Array): Promise<string> {
    const sha = BlobStore.sha256(data);
    return this.locked(sha, () => this.write(sha, data));
  }

  private async write(sha: string, data: Uint8Array): Promise<string> {
    const target = this.pathFor(sha);
    try {
      await fs.access(target);
      return sha;
    } catch {
      // not stored yet
    }
    await fs.mkdir(path.dirname(target), { recursive: true });
    const tmp = `${target}.${crypto.randomBytes(6).toString('hex')}.tmp`;
    const handle = await fs.open(tmp, 'w');
    try {
      await handle.writeFile(data);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await fs.rename(tmp, target);
    return sha;
  }

  async get(sha: string): Promise<Buffer> {
    const data = await fs.readFile(this.pathFor(sha));
    if (BlobStore.sha256(data) !== sha) throw new Error(`Blob ${sha} is corrupt on disk`);
    return data;
  }

  /** Deletes the blob if canDelete() still returns true once the blob's lock is held. */
  deleteIf(sha: string, canDelete: () => boolean): Promise<void> {
    return this.locked(sha, async () => {
      if (canDelete()) await fs.rm(this.pathFor(sha), { force: true });
    });
  }
}
