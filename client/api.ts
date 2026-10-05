import crypto from 'node:crypto';

/** The server could not be reached; the client should continue offline. */
export class OfflineError extends Error {}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: Record<string, unknown>;

  constructor(status: number, code: string, message: string, details: Record<string, unknown>) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export type Role = 'owner' | 'editor' | 'reader';

export interface VaultInfo {
  id: string;
  name: string;
  role: Role;
  revision: number;
  sha256: string | null;
  size: number | null;
  updatedAt: string | null;
  conflicts: number;
  /** Deletion protection is on. */
  protected: boolean;
}

export interface GroupInfo {
  id: number;
  name: string;
  createdAt: string;
  members: Array<{ userId: number; username: string }>;
}

export interface VaultGroup {
  groupId: number;
  name: string;
  role: Role;
}

export interface Download {
  revision: number;
  sha256: string;
  data: Uint8Array;
}

export interface UploadResult {
  revision: number;
  sha256: string;
  unchanged: boolean;
}

export interface ConnectionTest {
  ok: boolean;
  step: 'reach' | 'server' | 'login' | 'vault' | 'done';
  message: string;
  username?: string;
  vault?: VaultInfo;
}

export class KpsApi {
  readonly baseUrl: string;
  token?: string;
  private readonly timeoutMs: number;

  constructor(baseUrl: string, token?: string, timeoutMs = 30_000) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.token = token;
    this.timeoutMs = timeoutMs;
  }

  private async request(method: string, path: string, init: { body?: Uint8Array | string; headers?: Record<string, string> } = {}): Promise<Response> {
    const headers: Record<string, string> = { ...init.headers };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    if (typeof init.body === 'string') headers['Content-Type'] = 'application/json';
    let res: Response;
    try {
      res = await fetch(`${this.baseUrl}${path}`, {
        method, headers, body: init.body as BodyInit | undefined, signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (err) {
      throw new OfflineError(`Cannot reach ${this.baseUrl}: ${(err as Error).message}`, { cause: err });
    }
    if (res.status >= 500 && res.status !== 501) {
      // Gateway/proxy errors mean "server unavailable", which the client treats like being offline.
      throw new OfflineError(`Server unavailable (${res.status})`);
    }
    if (!res.ok && res.status !== 304) {
      let error: Record<string, unknown> = {};
      try {
        error = ((await res.json()) as { error?: Record<string, unknown> }).error ?? {};
      } catch {
        // not JSON
      }
      const { code, message, ...details } = error;
      throw new ApiError(res.status, String(code ?? 'http_error'), String(message ?? res.statusText), details);
    }
    return res;
  }

  private async json<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.request(method, path, { body: body === undefined ? undefined : JSON.stringify(body) });
    return (await res.json()) as T;
  }

  status() {
    return this.json<{ server: string; apiVersion: number }>('GET', '/api/v1/status');
  }

  async login(username: string, password: string, deviceName: string): Promise<string> {
    const { token } = await this.json<{ token: string }>('POST', '/api/v1/auth/login', { username, password, deviceName });
    this.token = token;
    return token;
  }

  async logout(): Promise<void> {
    await this.json('POST', '/api/v1/auth/logout');
    this.token = undefined;
  }

  me() {
    return this.json<{ id: number; username: string; isAdmin: boolean }>('GET', '/api/v1/me');
  }

  listVaults() {
    return this.json<VaultInfo[]>('GET', '/api/v1/vaults');
  }

  getVault(id: string) {
    return this.json<VaultInfo>('GET', `/api/v1/vaults/${encodeURIComponent(id)}`);
  }

  /** Creates a vault; `groups` shares it with those groups right away. */
  createVault(name: string, groups?: Array<{ name: string; role: Role }>) {
    return this.json<VaultInfo>('POST', '/api/v1/vaults', groups?.length ? { name, groups } : { name });
  }

  /** Owner: renames a vault. */
  renameVault(id: string, name: string) {
    return this.json<VaultInfo>('PATCH', `/api/v1/vaults/${encodeURIComponent(id)}`, { name });
  }

  /** Owner: turns deletion protection on or off. */
  setVaultProtected(id: string, value: boolean) {
    return this.json<VaultInfo>('PATCH', `/api/v1/vaults/${encodeURIComponent(id)}`, { protected: value });
  }

  /** Owner: deletes a vault with all its revisions and conflict copies (fails with 409 while protected). */
  async deleteVault(id: string): Promise<void> {
    await this.json('DELETE', `/api/v1/vaults/${encodeURIComponent(id)}`);
  }

  /** Copies a vault (current database only); the caller owns the copy. `copySharing` needs the owner role. */
  duplicateVault(id: string, name?: string, copySharing = false) {
    return this.json<VaultInfo>('POST', `/api/v1/vaults/${encodeURIComponent(id)}/duplicate`, { ...(name ? { name } : {}), copySharing });
  }

  // --- groups (create/rename/delete/members are administrator only) ---------------------------

  listGroups() {
    return this.json<GroupInfo[]>('GET', '/api/v1/groups');
  }

  createGroup(name: string, members: string[] = []) {
    return this.json<GroupInfo>('POST', '/api/v1/groups', { name, members });
  }

  renameGroup(groupId: number, name: string) {
    return this.json<GroupInfo>('PATCH', `/api/v1/groups/${groupId}`, { name });
  }

  async deleteGroup(groupId: number): Promise<void> {
    await this.json('DELETE', `/api/v1/groups/${groupId}`);
  }

  addGroupMember(groupId: number, username: string) {
    return this.json<GroupInfo>('PUT', `/api/v1/groups/${groupId}/members/${encodeURIComponent(username)}`);
  }

  removeGroupMember(groupId: number, username: string) {
    return this.json<GroupInfo>('DELETE', `/api/v1/groups/${groupId}/members/${encodeURIComponent(username)}`);
  }

  vaultGroups(vaultId: string) {
    return this.json<VaultGroup[]>('GET', `/api/v1/vaults/${encodeURIComponent(vaultId)}/groups`);
  }

  /** Owner: gives a group a role on the vault (or changes it). */
  shareWithGroup(vaultId: string, groupName: string, role: Role) {
    return this.json<VaultGroup>('PUT', `/api/v1/vaults/${encodeURIComponent(vaultId)}/groups/${encodeURIComponent(groupName)}`, { role });
  }

  async unshareGroup(vaultId: string, groupName: string): Promise<void> {
    await this.json('DELETE', `/api/v1/vaults/${encodeURIComponent(vaultId)}/groups/${encodeURIComponent(groupName)}`);
  }

  /** Downloads the current database, or returns null when it is still at `knownRevision`. */
  async download(vaultId: string, knownRevision?: number): Promise<Download | null> {
    const headers: Record<string, string> = {};
    if (knownRevision) headers['If-None-Match'] = `"${knownRevision}"`;
    const res = await this.request('GET', `/api/v1/vaults/${encodeURIComponent(vaultId)}/content`, { headers });
    if (res.status === 304) return null;
    const data = new Uint8Array(await res.arrayBuffer());
    const sha256 = res.headers.get('X-KPS-SHA256') ?? '';
    if (crypto.createHash('sha256').update(data).digest('hex') !== sha256) {
      throw new OfflineError('Download was incomplete (checksum mismatch)');
    }
    return { revision: Number(res.headers.get('X-KPS-Revision')), sha256, data };
  }

  /** Uploads a new revision based on `baseRevision`; throws ApiError 412 (code "conflict") when that is stale. */
  async upload(vaultId: string, data: Uint8Array, baseRevision: number | '*', note?: string): Promise<UploadResult> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/octet-stream',
      'If-Match': baseRevision === '*' ? '*' : `"${baseRevision}"`,
      'X-KPS-SHA256': crypto.createHash('sha256').update(data).digest('hex'),
    };
    if (note) headers['X-KPS-Note'] = encodeURIComponent(note);
    const res = await this.request('PUT', `/api/v1/vaults/${encodeURIComponent(vaultId)}/content`, { body: data, headers });
    return (await res.json()) as UploadResult;
  }

  async uploadConflict(vaultId: string, data: Uint8Array, baseRevision: number, reason: string): Promise<string> {
    const res = await this.request('POST', `/api/v1/vaults/${encodeURIComponent(vaultId)}/conflicts`, {
      body: data,
      headers: {
        'Content-Type': 'application/octet-stream',
        'X-KPS-Base-Revision': String(baseRevision),
        'X-KPS-Reason': encodeURIComponent(reason),
      },
    });
    return ((await res.json()) as { id: string }).id;
  }

  /** Long-polls until the vault revision differs from `since` (or the timeout passes). */
  async waitForChange(vaultId: string, since: number, timeoutSeconds = 25): Promise<number> {
    const { revision } = await this.json<{ revision: number }>(
      'GET', `/api/v1/vaults/${encodeURIComponent(vaultId)}/wait?since=${since}&timeout=${timeoutSeconds}`,
    );
    return revision;
  }

  /**
   * What a "Test connection" button runs: is it reachable, is it a keepass-server, do the
   * credentials work, and (optionally) can this user write to the vault.
   */
  static async testConnection(baseUrl: string, username: string, password: string, vaultId?: string): Promise<ConnectionTest> {
    const api = new KpsApi(baseUrl, undefined, 10_000);
    try {
      const status = await api.status();
      if (status.server !== 'keepass-server') return { ok: false, step: 'server', message: 'This URL is not a keepass-server' };
    } catch (err) {
      if (err instanceof OfflineError) return { ok: false, step: 'reach', message: err.message };
      return { ok: false, step: 'server', message: 'This URL is not a keepass-server' };
    }
    try {
      await api.login(username, password, 'connection test');
    } catch (err) {
      return { ok: false, step: 'login', message: (err as Error).message };
    }
    try {
      const me = await api.me();
      if (vaultId) {
        const vault = await api.getVault(vaultId);
        if (vault.role === 'reader') {
          return { ok: false, step: 'vault', message: 'Read-only access to this vault', username: me.username, vault };
        }
        return { ok: true, step: 'done', message: `Connected as ${me.username}`, username: me.username, vault };
      }
      return { ok: true, step: 'done', message: `Connected as ${me.username}`, username: me.username };
    } catch (err) {
      return { ok: false, step: 'vault', message: (err as Error).message };
    } finally {
      await api.logout().catch(() => undefined);
    }
  }
}
