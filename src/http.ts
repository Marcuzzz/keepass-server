import type { IncomingMessage, ServerResponse } from 'node:http';
import type { AuthUser } from './auth.ts';

export class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: Record<string, unknown>;

  constructor(status: number, code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  params: Record<string, string>;
  ip: string;
  user?: AuthUser;
}

export type Handler = (ctx: Ctx) => Promise<void> | void;

interface Route {
  method: string;
  path: string;
  pattern: RegExp;
  keys: string[];
  handler: Handler;
}

export class Router {
  private readonly routes: Route[] = [];

  add(method: string, path: string, handler: Handler): void {
    const keys: string[] = [];
    const source = path.replace(/:([a-zA-Z]+)/g, (_, key: string) => {
      keys.push(key);
      return '([^/]+)';
    });
    this.routes.push({ method, path, pattern: new RegExp(`^${source}$`), keys, handler });
  }

  list(): Array<{ method: string; path: string }> {
    return this.routes.map(({ method, path }) => ({ method, path }));
  }

  /** Returns the handler and params, or the allowed methods when only the method does not match. */
  match(method: string, pathname: string): { handler: Handler; params: Record<string, string> } | { allowed: string[] } | null {
    const allowed: string[] = [];
    for (const route of this.routes) {
      const m = route.pattern.exec(pathname);
      if (!m) continue;
      const routeMethod = route.method === 'GET' && method === 'HEAD' ? 'HEAD' : route.method;
      if (routeMethod !== method) {
        allowed.push(route.method);
        continue;
      }
      const params: Record<string, string> = {};
      route.keys.forEach((key, i) => {
        params[key] = decodeURIComponent(m[i + 1]!);
      });
      return { handler: route.handler, params };
    }
    return allowed.length ? { allowed } : null;
  }
}

export function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(data),
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(res.req.method === 'HEAD' ? undefined : data);
}

export function sendError(res: ServerResponse, err: HttpError): void {
  sendJson(res, err.status, { error: { code: err.code, message: err.message, ...err.details } });
}

export async function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  const declared = Number(req.headers['content-length']);
  if (Number.isFinite(declared) && declared > limit) {
    throw new HttpError(413, 'payload_too_large', `Body exceeds ${limit} bytes`);
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) throw new HttpError(413, 'payload_too_large', `Body exceeds ${limit} bytes`);
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

export async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const body = await readBody(req, 64 * 1024);
  if (body.length === 0) return {};
  try {
    const value: unknown = JSON.parse(body.toString('utf8'));
    if (value && typeof value === 'object' && !Array.isArray(value)) return value as Record<string, unknown>;
  } catch {
    // fall through
  }
  throw new HttpError(400, 'invalid_json', 'Body must be a JSON object');
}

/** Parses an If-Match / If-None-Match value into revision numbers; '*' is returned as is. */
export function parseEtagList(header: string | undefined): Array<number | '*'> | undefined {
  if (header === undefined) return undefined;
  if (header.trim() === '*') return ['*'];
  return header.split(',').map((part) => {
    const value = part.trim().replace(/^W\//, '').replace(/^"|"$/g, '');
    const n = Number(value);
    if (!Number.isInteger(n) || n < 0) throw new HttpError(400, 'invalid_etag', `Invalid revision in header: ${part}`);
    return n;
  });
}

export function etag(rev: number): string {
  return `"${rev}"`;
}

export function requireString(body: Record<string, unknown>, key: string, max = 200): string {
  const value = body[key];
  if (typeof value !== 'string' || value.trim() === '' || value.length > max) {
    throw new HttpError(400, 'invalid_request', `Field "${key}" must be a non-empty string (max ${max})`);
  }
  return value.trim();
}

export function requireUser(ctx: Ctx): AuthUser {
  if (!ctx.user) throw new HttpError(401, 'unauthorized', 'Authentication required');
  return ctx.user;
}

export function requireAdmin(ctx: Ctx): AuthUser {
  const user = requireUser(ctx);
  if (!user.isAdmin) throw new HttpError(403, 'forbidden', 'Administrator only');
  return user;
}
