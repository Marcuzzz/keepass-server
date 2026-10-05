import { argon2d, argon2id } from 'hash-wasm';
import kdbxweb from 'kdbxweb';

export { kdbxweb };
export type Kdbx = kdbxweb.Kdbx;

// kdbxweb ships without an Argon2 implementation; KeePassXC/KeePassDX create Argon2 databases by default.
kdbxweb.CryptoEngine.setArgon2Impl(async (password, salt, memory, iterations, length, parallelism, type, version) => {
  if (version !== 0x13) throw new Error('Only Argon2 version 1.3 is supported');
  const options = {
    password: new Uint8Array(password),
    salt: new Uint8Array(salt),
    memorySize: memory, // KiB
    iterations,
    hashLength: length,
    parallelism,
    outputType: 'binary' as const,
  };
  const hash = type === kdbxweb.CryptoEngine.Argon2TypeArgon2id ? await argon2id(options) : await argon2d(options);
  return hash.buffer.slice(hash.byteOffset, hash.byteOffset + hash.byteLength) as ArrayBuffer;
});

export function credentials(password: string, keyFile?: Uint8Array): kdbxweb.Credentials {
  return new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString(password), keyFile ?? null);
}

export function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  return data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
}

export function loadKdbx(data: Uint8Array, creds: kdbxweb.Credentials): Promise<Kdbx> {
  return kdbxweb.Kdbx.load(toArrayBuffer(data), creds);
}

export async function saveKdbx(db: Kdbx): Promise<Uint8Array> {
  return new Uint8Array(await db.save());
}

export function isInvalidKey(err: unknown): boolean {
  return err instanceof kdbxweb.KdbxError && err.code === kdbxweb.Consts.ErrorCodes.InvalidKey;
}
