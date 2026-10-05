import crypto from 'node:crypto';
import { promisify } from 'node:util';
import type { Db } from './db.ts';
import { now } from './db.ts';

const scrypt = promisify(crypto.scrypt) as (
  password: crypto.BinaryLike,
  salt: crypto.BinaryLike,
  keylen: number,
  options: crypto.ScryptOptions,
) => Promise<Buffer>;

const SCRYPT = { N: 1 << 15, r: 8, p: 1, keylen: 32 };
const DAY = 24 * 60 * 60 * 1000;

export interface AuthUser {
  id: number;
  username: string;
  isAdmin: boolean;
  tokenId: number;
  deviceName: string;
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password, salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: 64 * 1024 * 1024 });
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('base64'), hash.toString('base64')].join('$');
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [algo, n, r, p, salt, hash] = stored.split('$');
  if (algo !== 'scrypt' || !n || !r || !p || !salt || !hash) return false;
  const expected = Buffer.from(hash, 'base64');
  const actual = await scrypt(password, Buffer.from(salt, 'base64'), expected.length, {
    N: Number(n), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024,
  });
  return crypto.timingSafeEqual(actual, expected);
}

/** Hash computed on every login with an unknown username, so timing does not reveal valid names. */
let dummyHash: Promise<string> | undefined;
export function dummyPasswordHash(): Promise<string> {
  dummyHash ??= hashPassword(crypto.randomBytes(16).toString('hex'));
  return dummyHash;
}

export function validatePassword(password: unknown): string {
  if (typeof password !== 'string' || password.length < 10) {
    throw new Error('Password must be at least 10 characters');
  }
  return password;
}

export function validateUsername(username: unknown): string {
  if (typeof username !== 'string' || !/^[A-Za-z0-9._@-]{2,64}$/.test(username)) {
    throw new Error('Username must be 2-64 characters: letters, digits, . _ @ -');
  }
  return username;
}

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function issueToken(db: Db, userId: number, deviceName: string, ttlDays: number): string {
  const token = `kps_${crypto.randomBytes(32).toString('base64url')}`;
  const t = now();
  db.prepare(
    'INSERT INTO tokens (user_id, token_hash, device_name, created_at, last_used_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
  ).run(userId, hashToken(token), deviceName.slice(0, 100), t, t, t + ttlDays * DAY);
  return token;
}

/** Resolves a bearer token. Tokens are sliding: every use extends the expiry. */
export function authenticateToken(db: Db, token: string, ttlDays: number): AuthUser | null {
  const row = db.prepare(`
    SELECT t.id AS token_id, t.device_name, t.expires_at, t.last_used_at, u.id, u.username, u.is_admin
    FROM tokens t JOIN users u ON u.id = t.user_id
    WHERE t.token_hash = ? AND u.disabled = 0
  `).get(hashToken(token)) as
    | { token_id: number; device_name: string; expires_at: number; last_used_at: number; id: number; username: string; is_admin: number }
    | undefined;
  if (!row) return null;
  const t = now();
  if (row.expires_at < t) {
    db.prepare('DELETE FROM tokens WHERE id = ?').run(row.token_id);
    return null;
  }
  // Avoid a write on every request.
  if (t - row.last_used_at > 60_000) {
    db.prepare('UPDATE tokens SET last_used_at = ?, expires_at = ? WHERE id = ?').run(t, t + ttlDays * DAY, row.token_id);
  }
  return { id: row.id, username: row.username, isAdmin: row.is_admin === 1, tokenId: row.token_id, deviceName: row.device_name };
}

/**
 * Per (ip, username) login throttling: after 5 failures each further failure doubles the lockout,
 * capped at 15 minutes.
 */
export class LoginThrottle {
  private readonly failures = new Map<string, { count: number; until: number }>();

  retryAfterMs(key: string): number {
    const entry = this.failures.get(key);
    return entry ? Math.max(0, entry.until - Date.now()) : 0;
  }

  fail(key: string): void {
    const entry = this.failures.get(key) ?? { count: 0, until: 0 };
    entry.count++;
    if (entry.count >= 5) {
      entry.until = Date.now() + Math.min(15 * 60_000, 1000 * 2 ** (entry.count - 5));
    }
    this.failures.set(key, entry);
    if (this.failures.size > 10_000) this.failures.clear();
  }

  succeed(key: string): void {
    this.failures.delete(key);
  }
}
