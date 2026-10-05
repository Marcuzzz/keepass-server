import path from 'node:path';

export interface TlsConfig {
  certFile: string;
  keyFile: string;
}

export interface Config {
  host: string;
  port: number;
  dataDir: string;
  maxUploadBytes: number;
  /** Always keep at least this many most recent revisions per vault. */
  keepRevisions: number;
  /** Also keep every revision younger than this many days. */
  keepDays: number;
  tokenTtlDays: number;
  trustProxy: boolean;
  tls?: TlsConfig;
  bootstrapAdmin?: { username: string; password: string };
}

function int(value: string | undefined, fallback: number): number {
  if (value === undefined || value === '') return fallback;
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n) || n < 0) throw new Error(`Invalid number: ${value}`);
  return n;
}

function bool(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const config: Config = {
    host: env.KPS_HOST ?? '0.0.0.0',
    port: int(env.KPS_PORT, 8787),
    dataDir: path.resolve(env.KPS_DATA_DIR ?? './data'),
    maxUploadBytes: int(env.KPS_MAX_UPLOAD_MB, 50) * 1024 * 1024,
    keepRevisions: Math.max(1, int(env.KPS_KEEP_REVISIONS, 50)),
    keepDays: int(env.KPS_KEEP_DAYS, 30),
    tokenTtlDays: int(env.KPS_TOKEN_TTL_DAYS, 365),
    trustProxy: bool(env.KPS_TRUST_PROXY, false),
  };
  if (env.KPS_TLS_CERT && env.KPS_TLS_KEY) {
    config.tls = { certFile: env.KPS_TLS_CERT, keyFile: env.KPS_TLS_KEY };
  }
  if (env.KPS_ADMIN_USERNAME && env.KPS_ADMIN_PASSWORD) {
    config.bootstrapAdmin = { username: env.KPS_ADMIN_USERNAME, password: env.KPS_ADMIN_PASSWORD };
  }
  return config;
}
