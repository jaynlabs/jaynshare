const PREFIX = 'JAYNSHARE-PREF-v1-';
const MAX_IDENTITY_BYTES = 1024;

export const ACCOUNT_PREFERENCE_PREFIX = PREFIX;

export function encodeAccountPreference(identity: string): string {
  if (typeof identity !== 'string' || !identity.trim()) {
    throw new TypeError('account preference must be a non-empty string');
  }
  const bytes = Buffer.from(identity, 'utf8');
  if (bytes.length > MAX_IDENTITY_BYTES) throw new RangeError('account preference is too long');
  return PREFIX + bytes.toString('base64url');
}

// null: not a preference (a plain account pin). Throws: a malformed one must never route automatically.
export function decodeAccountPreference(value: unknown): string | null {
  if (typeof value !== 'string' || !value.startsWith(PREFIX)) return null;
  const encoded = value.slice(PREFIX.length);
  if (!encoded || encoded.length > Math.ceil(MAX_IDENTITY_BYTES * 4 / 3)
      || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
    throw new Error('malformed account preference');
  }
  const bytes = Buffer.from(encoded, 'base64url');
  if (!bytes.length || bytes.length > MAX_IDENTITY_BYTES
      || bytes.toString('base64url') !== encoded) {
    throw new Error('malformed account preference');
  }
  let identity: string;
  try { identity = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { throw new Error('malformed account preference'); }
  if (!identity.trim() || /[\0\r\n]/.test(identity)) throw new Error('malformed account preference');
  return identity;
}
