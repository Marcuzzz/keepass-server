import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { KpsApi } from '../client/api.ts';
import { credentials, type Kdbx, kdbxweb, saveKdbx } from '../client/kdbx.ts';
import type { Config } from '../src/config.ts';
import { createKeepassServer, type KeepassServer } from '../src/server.ts';

export const ADMIN = { username: 'admin', password: 'admin-password-1' };
export const DB_PASSWORD = 'correct horse battery staple';

export interface TestServer {
  app: KeepassServer;
  url: string;
  dataDir: string;
  stop(): Promise<void>;
}

export async function tempDir(prefix = 'kps-test-'): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix));
}

export async function startServer(overrides: Partial<Config> = {}): Promise<TestServer> {
  const dataDir = overrides.dataDir ?? (await tempDir());
  const app = await createKeepassServer({
    host: '127.0.0.1',
    port: 0,
    dataDir,
    maxUploadBytes: 5 * 1024 * 1024,
    keepRevisions: 50,
    keepDays: 30,
    tokenTtlDays: 30,
    trustProxy: false,
    bootstrapAdmin: ADMIN,
    ...overrides,
  });
  const { port } = await app.listen();
  return { app, url: `http://127.0.0.1:${port}`, dataDir, stop: () => app.close() };
}

export async function adminApi(url: string): Promise<KpsApi> {
  const api = new KpsApi(url);
  await api.login(ADMIN.username, ADMIN.password, 'test admin');
  return api;
}

/** Raw request helper for asserting status codes and headers. */
export async function call(url: string, token: string | undefined, method: string, p: string, body?: unknown, headers: Record<string, string> = {}): Promise<Response> {
  const h: Record<string, string> = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  let payload: BodyInit | undefined;
  if (body instanceof Uint8Array) payload = body as BodyInit;
  else if (body !== undefined) {
    payload = JSON.stringify(body);
    h['Content-Type'] = 'application/json';
  }
  return fetch(`${url}${p}`, { method, headers: h, body: payload });
}

export async function createUser(url: string, adminToken: string, username: string, password = 'user-password-1'): Promise<KpsApi> {
  const res = await call(url, adminToken, 'POST', '/api/v1/users', { username, password });
  if (res.status !== 201) throw new Error(`createUser ${res.status}: ${await res.text()}`);
  const api = new KpsApi(url);
  await api.login(username, password, `${username} device`);
  return api;
}

export function newDatabase(password = DB_PASSWORD): Kdbx {
  const db = kdbxweb.Kdbx.create(credentials(password), 'Test');
  return db;
}

export function addEntry(db: Kdbx, title: string, password = 'secret'): kdbxweb.KdbxEntry {
  const entry = db.createEntry(db.getDefaultGroup());
  entry.fields.set('Title', title);
  entry.fields.set('Password', kdbxweb.ProtectedValue.fromString(password));
  entry.times.update();
  return entry;
}

export function findEntry(db: Kdbx, title: string): kdbxweb.KdbxEntry | undefined {
  for (const entry of db.getDefaultGroup().allEntries()) {
    if (entry.fields.get('Title') === title) return entry;
  }
  return undefined;
}

export function titles(db: Kdbx): string[] {
  const out: string[] = [];
  for (const entry of db.getDefaultGroup().allEntries()) {
    if (entry.parentGroup?.uuid.equals(db.meta.recycleBinUuid)) continue;
    out.push(String(entry.fields.get('Title')));
  }
  return out.sort();
}

export async function databaseBytes(db: Kdbx): Promise<Uint8Array> {
  return saveKdbx(db);
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
