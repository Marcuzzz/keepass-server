import {
  authenticateToken, dummyPasswordHash, hashPassword, issueToken, LoginThrottle,
  validatePassword, validateUsername, verifyPassword,
} from './auth.ts';
import type { Config } from './config.ts';
import { type Db, now, transaction } from './db.ts';
import {
  type Ctx, etag, HttpError, parseEtagList, readBody, readJson, requireAdmin, requireString, requireUser, Router, sendJson,
} from './http.ts';
import { type Role, VaultService } from './vaults.ts';

export const API_VERSION = 1;
const ROLES: Role[] = ['owner', 'editor', 'reader'];

interface UserRow {
  id: number;
  username: string;
  password_hash: string;
  is_admin: number;
  disabled: number;
  created_at: number;
}

function publicUser(u: Pick<UserRow, 'id' | 'username' | 'is_admin' | 'disabled' | 'created_at'>) {
  return {
    id: u.id,
    username: u.username,
    isAdmin: u.is_admin === 1,
    disabled: u.disabled === 1,
    createdAt: new Date(u.created_at).toISOString(),
  };
}

function badRequest(fn: () => string): string {
  try {
    return fn();
  } catch (err) {
    throw new HttpError(400, 'invalid_request', (err as Error).message);
  }
}

function intParam(value: string | undefined, name: string): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) throw new HttpError(400, 'invalid_request', `Invalid ${name}`);
  return n;
}

function sendKdbx(ctx: Ctx, data: Buffer, rev: number, sha: string, filename: string): void {
  ctx.res.writeHead(200, {
    'Content-Type': 'application/octet-stream',
    'Content-Length': data.length,
    'Content-Disposition': `attachment; filename="${filename.replace(/[^A-Za-z0-9._ -]/g, '_')}.kdbx"`,
    'Cache-Control': 'no-store',
    ETag: etag(rev),
    'X-KPS-Revision': String(rev),
    'X-KPS-SHA256': sha,
  });
  ctx.res.end(ctx.req.method === 'HEAD' ? undefined : data);
}

export function buildApi(db: Db, config: Config, vaults: VaultService): { router: Router; authenticate: (ctx: Ctx) => void } {
  const router = new Router();
  const throttle = new LoginThrottle();

  const authenticate = (ctx: Ctx): void => {
    const header = ctx.req.headers.authorization;
    if (!header?.startsWith('Bearer ')) return;
    const user = authenticateToken(db, header.slice(7).trim(), config.tokenTtlDays);
    if (!user) throw new HttpError(401, 'invalid_token', 'Token is invalid, expired or revoked');
    ctx.user = user;
  };

  const getUser = (id: number): UserRow => {
    const row = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
    if (!row) throw new HttpError(404, 'user_not_found', 'User not found');
    return row;
  };

  const adminCount = (): number =>
    (db.prepare('SELECT COUNT(*) AS n FROM users WHERE is_admin = 1 AND disabled = 0').get() as { n: number }).n;

  // --- status & auth ------------------------------------------------------------------------------

  router.add('GET', '/api/v1/status', (ctx) => {
    sendJson(ctx.res, 200, { server: 'keepass-server', apiVersion: API_VERSION, time: new Date().toISOString() });
  });

  router.add('POST', '/api/v1/auth/login', async (ctx) => {
    const body = await readJson(ctx.req);
    const username = requireString(body, 'username', 64);
    const password = requireString(body, 'password', 1024);
    const deviceName = typeof body.deviceName === 'string' && body.deviceName.trim() ? body.deviceName.trim() : 'unknown device';
    const key = `${ctx.ip}|${username.toLowerCase()}`;
    const wait = throttle.retryAfterMs(key);
    if (wait > 0) {
      throw new HttpError(429, 'too_many_attempts', 'Too many failed logins, try again later', { retryAfterSeconds: Math.ceil(wait / 1000) });
    }
    const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username) as UserRow | undefined;
    const ok = await verifyPassword(password, row?.password_hash ?? (await dummyPasswordHash()));
    if (!row || !ok || row.disabled) {
      throttle.fail(key);
      throw new HttpError(401, 'invalid_credentials', 'Invalid username or password');
    }
    throttle.succeed(key);
    const token = issueToken(db, row.id, deviceName, config.tokenTtlDays);
    sendJson(ctx.res, 200, { token, user: publicUser(row) });
  });

  router.add('POST', '/api/v1/auth/logout', (ctx) => {
    const user = requireUser(ctx);
    db.prepare('DELETE FROM tokens WHERE id = ?').run(user.tokenId);
    sendJson(ctx.res, 200, { ok: true });
  });

  router.add('GET', '/api/v1/me', (ctx) => {
    const user = requireUser(ctx);
    sendJson(ctx.res, 200, { ...publicUser(getUser(user.id)), deviceName: user.deviceName });
  });

  router.add('POST', '/api/v1/me/password', async (ctx) => {
    const user = requireUser(ctx);
    const body = await readJson(ctx.req);
    const current = requireString(body, 'currentPassword', 1024);
    const next = badRequest(() => validatePassword(body.newPassword));
    if (!(await verifyPassword(current, getUser(user.id).password_hash))) {
      throw new HttpError(403, 'invalid_credentials', 'Current password is wrong');
    }
    const hash = await hashPassword(next);
    transaction(db, () => {
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id);
      db.prepare('DELETE FROM tokens WHERE user_id = ? AND id <> ?').run(user.id, user.tokenId);
    });
    sendJson(ctx.res, 200, { ok: true });
  });

  router.add('GET', '/api/v1/me/tokens', (ctx) => {
    const user = requireUser(ctx);
    const rows = db.prepare('SELECT id, device_name, created_at, last_used_at, expires_at FROM tokens WHERE user_id = ? ORDER BY last_used_at DESC')
      .all(user.id) as Array<{ id: number; device_name: string; created_at: number; last_used_at: number; expires_at: number }>;
    sendJson(ctx.res, 200, rows.map((r) => ({
      id: r.id,
      deviceName: r.device_name,
      current: r.id === user.tokenId,
      createdAt: new Date(r.created_at).toISOString(),
      lastUsedAt: new Date(r.last_used_at).toISOString(),
      expiresAt: new Date(r.expires_at).toISOString(),
    })));
  });

  router.add('DELETE', '/api/v1/me/tokens/:id', (ctx) => {
    const user = requireUser(ctx);
    const result = db.prepare('DELETE FROM tokens WHERE id = ? AND user_id = ?').run(intParam(ctx.params.id, 'token id'), user.id);
    if (result.changes === 0) throw new HttpError(404, 'token_not_found', 'Token not found');
    sendJson(ctx.res, 200, { ok: true });
  });

  // --- user administration -------------------------------------------------------------------------

  router.add('GET', '/api/v1/users', (ctx) => {
    requireAdmin(ctx);
    const rows = db.prepare('SELECT * FROM users ORDER BY username COLLATE NOCASE').all() as unknown as UserRow[];
    sendJson(ctx.res, 200, rows.map(publicUser));
  });

  router.add('POST', '/api/v1/users', async (ctx) => {
    requireAdmin(ctx);
    const body = await readJson(ctx.req);
    const username = badRequest(() => validateUsername(body.username));
    const password = badRequest(() => validatePassword(body.password));
    if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) {
      throw new HttpError(409, 'user_exists', 'Username already taken');
    }
    const hash = await hashPassword(password);
    const result = db.prepare('INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)')
      .run(username, hash, body.isAdmin === true ? 1 : 0, now());
    sendJson(ctx.res, 201, publicUser(getUser(Number(result.lastInsertRowid))));
  });

  router.add('PATCH', '/api/v1/users/:id', async (ctx) => {
    const admin = requireAdmin(ctx);
    const target = getUser(intParam(ctx.params.id, 'user id'));
    const body = await readJson(ctx.req);
    const removesAdmin = target.is_admin === 1 && !target.disabled && (body.isAdmin === false || body.disabled === true);
    if (removesAdmin && adminCount() <= 1) {
      throw new HttpError(409, 'last_admin', 'Cannot remove the last active administrator');
    }
    if (target.id === admin.id && body.disabled === true) {
      throw new HttpError(409, 'self_disable', 'You cannot disable your own account');
    }
    const hash = body.password !== undefined ? await hashPassword(badRequest(() => validatePassword(body.password))) : undefined;
    transaction(db, () => {
      if (hash) {
        db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, target.id);
        db.prepare('DELETE FROM tokens WHERE user_id = ?').run(target.id);
      }
      if (typeof body.isAdmin === 'boolean') db.prepare('UPDATE users SET is_admin = ? WHERE id = ?').run(body.isAdmin ? 1 : 0, target.id);
      if (typeof body.disabled === 'boolean') {
        db.prepare('UPDATE users SET disabled = ? WHERE id = ?').run(body.disabled ? 1 : 0, target.id);
        if (body.disabled) db.prepare('DELETE FROM tokens WHERE user_id = ?').run(target.id);
      }
    });
    sendJson(ctx.res, 200, publicUser(getUser(target.id)));
  });

  router.add('DELETE', '/api/v1/users/:id', (ctx) => {
    const admin = requireAdmin(ctx);
    const target = getUser(intParam(ctx.params.id, 'user id'));
    if (target.id === admin.id) throw new HttpError(409, 'self_delete', 'You cannot delete your own account');
    if (target.is_admin === 1 && !target.disabled && adminCount() <= 1) {
      throw new HttpError(409, 'last_admin', 'Cannot delete the last active administrator');
    }
    const soleOwner = db.prepare(`
      SELECT v.name FROM vault_members m JOIN vaults v ON v.id = m.vault_id
      WHERE m.user_id = ? AND m.role = 'owner'
        AND (SELECT COUNT(*) FROM vault_members o WHERE o.vault_id = m.vault_id AND o.role = 'owner') = 1
    `).all(target.id) as Array<{ name: string }>;
    if (soleOwner.length) {
      throw new HttpError(409, 'sole_owner', 'User is the only owner of some vaults; transfer ownership first', {
        vaults: soleOwner.map((v) => v.name),
      });
    }
    db.prepare('DELETE FROM users WHERE id = ?').run(target.id);
    sendJson(ctx.res, 200, { ok: true });
  });

  // --- vaults ---------------------------------------------------------------------------------------

  router.add('GET', '/api/v1/vaults', (ctx) => {
    sendJson(ctx.res, 200, vaults.list(requireUser(ctx)));
  });

  router.add('POST', '/api/v1/vaults', async (ctx) => {
    const user = requireUser(ctx);
    const name = requireString(await readJson(ctx.req), 'name', 200);
    const vault = vaults.create(user, name);
    sendJson(ctx.res, 201, vaults.describe(vault, 'owner'));
  });

  router.add('GET', '/api/v1/vaults/:id', (ctx) => {
    const { vault, role } = vaults.access(ctx.params.id!, requireUser(ctx));
    sendJson(ctx.res, 200, vaults.describe(vault, role));
  });

  router.add('PATCH', '/api/v1/vaults/:id', async (ctx) => {
    const { vault } = vaults.access(ctx.params.id!, requireUser(ctx), 'owner');
    vaults.rename(vault.id, requireString(await readJson(ctx.req), 'name', 200));
    const updated = vaults.access(vault.id, requireUser(ctx));
    sendJson(ctx.res, 200, vaults.describe(updated.vault, updated.role));
  });

  router.add('DELETE', '/api/v1/vaults/:id', async (ctx) => {
    const { vault } = vaults.access(ctx.params.id!, requireUser(ctx), 'owner');
    await vaults.remove(vault.id);
    sendJson(ctx.res, 200, { ok: true });
  });

  router.add('GET', '/api/v1/vaults/:id/content', async (ctx) => {
    const { vault } = vaults.access(ctx.params.id!, requireUser(ctx));
    const rev = vault.current_rev;
    if (rev === 0) {
      throw new HttpError(404, 'empty_vault', 'No database has been uploaded to this vault yet', { currentRevision: 0 });
    }
    const ifNoneMatch = parseEtagList(ctx.req.headers['if-none-match']);
    if (ifNoneMatch && (ifNoneMatch.includes('*') || ifNoneMatch.includes(rev))) {
      ctx.res.writeHead(304, { ETag: etag(rev), 'X-KPS-Revision': String(rev), 'Cache-Control': 'no-store' });
      ctx.res.end();
      return;
    }
    const { data, row } = await vaults.readRevision(vault.id, rev);
    sendKdbx(ctx, data, rev, row.sha256, vault.name);
  });

  router.add('PUT', '/api/v1/vaults/:id/content', async (ctx) => {
    const user = requireUser(ctx);
    const { vault } = vaults.access(ctx.params.id!, user, 'editor');
    let ifMatch = parseEtagList(ctx.req.headers['if-match']);
    if (!ifMatch && ctx.req.headers['if-none-match']?.trim() === '*') ifMatch = [0];
    if (!ifMatch) {
      throw new HttpError(428, 'precondition_required', 'Send If-Match with the revision your changes are based on ("0" for a new vault)');
    }
    const data = await readBody(ctx.req, config.maxUploadBytes);
    const note = ctx.req.headers['x-kps-note'];
    const result = await vaults.commit(vault.id, user, data, {
      ifMatch,
      note: typeof note === 'string' ? decodeURIComponent(note).slice(0, 500) : undefined,
      expectedSha256: typeof ctx.req.headers['x-kps-sha256'] === 'string' ? ctx.req.headers['x-kps-sha256'] : undefined,
    });
    sendJson(ctx.res, result.unchanged ? 200 : 201, result, { ETag: etag(result.revision), 'X-KPS-Revision': String(result.revision) });
  });

  router.add('GET', '/api/v1/vaults/:id/wait', async (ctx) => {
    const { vault } = vaults.access(ctx.params.id!, requireUser(ctx));
    const since = intParam(ctx.url.searchParams.get('since') ?? String(vault.current_rev), 'since');
    const timeout = Math.min(60, Math.max(1, Number(ctx.url.searchParams.get('timeout') ?? 25))) * 1000;
    const abort = new AbortController();
    ctx.res.on('close', () => abort.abort());
    const revision = await vaults.waitForChange(vault.id, since, timeout, abort.signal);
    if (!ctx.res.writableEnded && !ctx.res.destroyed) sendJson(ctx.res, 200, { revision, changed: revision !== since });
  });

  // --- revisions --------------------------------------------------------------------------------

  router.add('GET', '/api/v1/vaults/:id/revisions', (ctx) => {
    const { vault } = vaults.access(ctx.params.id!, requireUser(ctx));
    sendJson(ctx.res, 200, vaults.revisions(vault.id).map((r) => ({
      revision: r.rev,
      sha256: r.sha256,
      size: r.size,
      createdAt: new Date(r.created_at).toISOString(),
      username: r.username,
      deviceName: r.device_name,
      baseRevision: r.base_rev,
      note: r.note,
      current: r.rev === vault.current_rev,
    })));
  });

  router.add('GET', '/api/v1/vaults/:id/revisions/:rev/content', async (ctx) => {
    const { vault } = vaults.access(ctx.params.id!, requireUser(ctx));
    const rev = intParam(ctx.params.rev, 'revision');
    const { data, row } = await vaults.readRevision(vault.id, rev);
    sendKdbx(ctx, data, rev, row.sha256, `${vault.name}-r${rev}`);
  });

  router.add('POST', '/api/v1/vaults/:id/revisions/:rev/restore', async (ctx) => {
    const user = requireUser(ctx);
    const { vault } = vaults.access(ctx.params.id!, user, 'editor');
    const rev = intParam(ctx.params.rev, 'revision');
    const { data } = await vaults.readRevision(vault.id, rev);
    const result = await vaults.commit(vault.id, user, data, { ifMatch: ['*'], note: `Restored revision ${rev}` });
    sendJson(ctx.res, 201, result, { ETag: etag(result.revision) });
  });

  // --- conflict copies ----------------------------------------------------------------------------

  router.add('GET', '/api/v1/vaults/:id/conflicts', (ctx) => {
    const { vault } = vaults.access(ctx.params.id!, requireUser(ctx));
    sendJson(ctx.res, 200, vaults.conflicts(vault.id));
  });

  router.add('POST', '/api/v1/vaults/:id/conflicts', async (ctx) => {
    const user = requireUser(ctx);
    const { vault } = vaults.access(ctx.params.id!, user, 'editor');
    const data = await readBody(ctx.req, config.maxUploadBytes);
    const base = ctx.req.headers['x-kps-base-revision'];
    const reason = ctx.req.headers['x-kps-reason'];
    const id = await vaults.addConflict(
      vault.id, user, data,
      typeof base === 'string' ? intParam(base, 'X-KPS-Base-Revision') : null,
      typeof reason === 'string' ? decodeURIComponent(reason).slice(0, 500) : null,
    );
    sendJson(ctx.res, 201, { id });
  });

  router.add('GET', '/api/v1/vaults/:id/conflicts/:cid/content', async (ctx) => {
    const { vault } = vaults.access(ctx.params.id!, requireUser(ctx));
    const data = await vaults.readConflict(vault.id, ctx.params.cid!);
    ctx.res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': data.length,
      'Content-Disposition': `attachment; filename="conflict-${ctx.params.cid}.kdbx"`,
      'Cache-Control': 'no-store',
    });
    ctx.res.end(ctx.req.method === 'HEAD' ? undefined : data);
  });

  router.add('DELETE', '/api/v1/vaults/:id/conflicts/:cid', async (ctx) => {
    const { vault } = vaults.access(ctx.params.id!, requireUser(ctx), 'editor');
    await vaults.removeConflict(vault.id, ctx.params.cid!);
    sendJson(ctx.res, 200, { ok: true });
  });

  // --- members ------------------------------------------------------------------------------------

  router.add('GET', '/api/v1/vaults/:id/members', (ctx) => {
    const { vault } = vaults.access(ctx.params.id!, requireUser(ctx));
    const rows = db.prepare(`
      SELECT u.id, u.username, m.role FROM vault_members m JOIN users u ON u.id = m.user_id
      WHERE m.vault_id = ? ORDER BY u.username COLLATE NOCASE
    `).all(vault.id) as Array<{ id: number; username: string; role: Role }>;
    sendJson(ctx.res, 200, rows.map((r) => ({ userId: r.id, username: r.username, role: r.role })));
  });

  const ownerCount = (vaultId: string): number =>
    (db.prepare("SELECT COUNT(*) AS n FROM vault_members WHERE vault_id = ? AND role = 'owner'").get(vaultId) as { n: number }).n;

  const memberTarget = (vaultId: string, username: string) => {
    const target = db.prepare('SELECT id FROM users WHERE username = ?').get(username) as { id: number } | undefined;
    if (!target) throw new HttpError(404, 'user_not_found', 'User not found');
    const current = db.prepare('SELECT role FROM vault_members WHERE vault_id = ? AND user_id = ?').get(vaultId, target.id) as
      | { role: Role }
      | undefined;
    return { userId: target.id, role: current?.role };
  };

  router.add('PUT', '/api/v1/vaults/:id/members/:username', async (ctx) => {
    const { vault } = vaults.access(ctx.params.id!, requireUser(ctx), 'owner');
    const role = (await readJson(ctx.req)).role;
    if (typeof role !== 'string' || !ROLES.includes(role as Role)) {
      throw new HttpError(400, 'invalid_request', `role must be one of ${ROLES.join(', ')}`);
    }
    const target = memberTarget(vault.id, ctx.params.username!);
    if (target.role === 'owner' && role !== 'owner' && ownerCount(vault.id) <= 1) {
      throw new HttpError(409, 'last_owner', 'A vault needs at least one owner');
    }
    db.prepare('INSERT INTO vault_members (vault_id, user_id, role) VALUES (?, ?, ?) ON CONFLICT DO UPDATE SET role = excluded.role')
      .run(vault.id, target.userId, role);
    sendJson(ctx.res, 200, { username: ctx.params.username, role });
  });

  router.add('DELETE', '/api/v1/vaults/:id/members/:username', (ctx) => {
    const { vault } = vaults.access(ctx.params.id!, requireUser(ctx), 'owner');
    const target = memberTarget(vault.id, ctx.params.username!);
    if (!target.role) throw new HttpError(404, 'member_not_found', 'User is not a member of this vault');
    if (target.role === 'owner' && ownerCount(vault.id) <= 1) {
      throw new HttpError(409, 'last_owner', 'A vault needs at least one owner');
    }
    db.prepare('DELETE FROM vault_members WHERE vault_id = ? AND user_id = ?').run(vault.id, target.userId);
    sendJson(ctx.res, 200, { ok: true });
  });

  return { router, authenticate };
}
