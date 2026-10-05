import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildApi } from './api.ts';
import { hashPassword } from './auth.ts';
import type { Config } from './config.ts';
import { type Db, now, openDatabase } from './db.ts';
import { type Ctx, HttpError, type Router, sendError, sendJson } from './http.ts';
import { openApiSpec } from './openapi.ts';
import { BlobStore } from './storage.ts';
import { VaultService } from './vaults.ts';

const ROOT_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const PUBLIC_DIR = path.join(ROOT_DIR, 'public');
const FONTAWESOME_DIR = path.join(ROOT_DIR, 'node_modules', '@fortawesome', 'fontawesome-free');
/** Third-party assets served from node_modules (the CSP allows no CDNs). Only these exact files. */
const VENDOR_FILES: Record<string, string> = {
  '/vendor/fontawesome/css/fontawesome.min.css': path.join(FONTAWESOME_DIR, 'css', 'fontawesome.min.css'),
  '/vendor/fontawesome/css/solid.min.css': path.join(FONTAWESOME_DIR, 'css', 'solid.min.css'),
  '/vendor/fontawesome/webfonts/fa-solid-900.woff2': path.join(FONTAWESOME_DIR, 'webfonts', 'fa-solid-900.woff2'),
};
const STATIC_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
};

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
};

export interface ServerOptions {
  log?: (line: string) => void;
}

export interface KeepassServer {
  server: http.Server;
  router: Router;
  db: Db;
  vaults: VaultService;
  listen(): Promise<{ port: number }>;
  close(): Promise<void>;
}

export async function ensureBootstrapAdmin(db: Db, config: Config): Promise<boolean> {
  const { n } = db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number };
  if (n > 0 || !config.bootstrapAdmin) return false;
  db.prepare('INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, 1, ?)').run(
    config.bootstrapAdmin.username, await hashPassword(config.bootstrapAdmin.password), now(),
  );
  return true;
}

const STATIC_ALIASES: Record<string, string> = { '/': 'index.html', '/api/docs': 'api-docs.html' };

function serveStatic(ctx: Ctx): boolean {
  if (ctx.req.method !== 'GET' && ctx.req.method !== 'HEAD') return false;
  const vendor = VENDOR_FILES[ctx.url.pathname];
  const name = STATIC_ALIASES[ctx.url.pathname] ?? ctx.url.pathname.slice(1);
  if (!vendor && !/^[a-z0-9-]+\.[a-z0-9]+$/.test(name)) return false;
  const file = vendor ?? path.join(PUBLIC_DIR, name);
  const type = STATIC_TYPES[path.extname(file)];
  if (!type || !fs.existsSync(file)) return false;
  const data = fs.readFileSync(file);
  ctx.res.writeHead(200, { 'Content-Type': type, 'Content-Length': data.length, 'Cache-Control': vendor ? 'public, max-age=86400' : 'no-cache' });
  ctx.res.end(ctx.req.method === 'HEAD' ? undefined : data);
  return true;
}

export async function createKeepassServer(config: Config, options: ServerOptions = {}): Promise<KeepassServer> {
  const db = openDatabase(config.dataDir);
  if (await ensureBootstrapAdmin(db, config)) options.log?.(`Created administrator "${config.bootstrapAdmin!.username}"`);
  const vaults = new VaultService(db, new BlobStore(config.dataDir), config);
  const { router, authenticate } = buildApi(db, config, vaults);
  router.add('GET', '/api/openapi.json', (ctx) => sendJson(ctx.res, 200, openApiSpec, { 'Cache-Control': 'no-cache' }));

  const handle = async (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> => {
    const started = Date.now();
    const forwarded = config.trustProxy ? String(req.headers['x-forwarded-for'] ?? '').split(',')[0]?.trim() : '';
    const ctx: Ctx = {
      req, res,
      url: new URL(req.url ?? '/', 'http://localhost'),
      params: {},
      ip: forwarded || req.socket.remoteAddress || 'unknown',
    };
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.setHeader(k, v);
    try {
      const match = router.match(req.method ?? 'GET', ctx.url.pathname);
      if (match && 'handler' in match) {
        ctx.params = match.params;
        authenticate(ctx);
        await match.handler(ctx);
      } else if (match) {
        throw new HttpError(405, 'method_not_allowed', 'Method not allowed', { allowed: match.allowed });
      } else if (!serveStatic(ctx)) {
        throw new HttpError(404, 'not_found', 'Not found');
      }
    } catch (err) {
      if (res.headersSent) {
        res.destroy();
      } else if (err instanceof HttpError) {
        sendError(res, err);
      } else {
        options.log?.(`Error on ${req.method} ${ctx.url.pathname}: ${(err as Error).stack ?? String(err)}`);
        sendJson(res, 500, { error: { code: 'internal_error', message: 'Internal server error' } });
      }
    } finally {
      options.log?.(`${ctx.ip} ${ctx.user?.username ?? '-'} ${req.method} ${ctx.url.pathname} ${res.statusCode} ${Date.now() - started}ms`);
    }
  };

  const listener = (req: http.IncomingMessage, res: http.ServerResponse) => void handle(req, res);
  const server = config.tls
    ? https.createServer({ cert: fs.readFileSync(config.tls.certFile), key: fs.readFileSync(config.tls.keyFile) }, listener)
    : http.createServer(listener);
  server.requestTimeout = 5 * 60_000;

  return {
    server, router, db, vaults,
    listen: () => new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(config.port, config.host, () => {
        const address = server.address();
        resolve({ port: typeof address === 'object' && address ? address.port : config.port });
      });
    }),
    close: () => new Promise((resolve) => {
      server.closeAllConnections();
      server.close(() => {
        db.close();
        resolve();
      });
    }),
  };
}
