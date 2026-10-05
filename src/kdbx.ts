// KeePass file signature: 0x9AA2D903 0xB54BFB67 (little endian), followed by the format version.
const SIG1 = 0x9aa2d903;
const SIG2_KDBX = 0xb54bfb67;

export interface KdbxInfo {
  majorVersion: number;
  minorVersion: number;
}

/**
 * Cheap sanity check of an upload. The server cannot decrypt the file, but it can refuse
 * something that is obviously not a KeePass 2.x database (truncated upload, HTML error page...).
 */
export function inspectKdbx(data: Uint8Array): KdbxInfo | null {
  if (data.byteLength < 128) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (view.getUint32(0, true) !== SIG1 || view.getUint32(4, true) !== SIG2_KDBX) return null;
  const minorVersion = view.getUint16(8, true);
  const majorVersion = view.getUint16(10, true);
  if (majorVersion !== 3 && majorVersion !== 4) return null;
  return { majorVersion, minorVersion };
}
