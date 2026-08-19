/**
 * Application-layer encryption for per-principal model credentials.
 *
 * The database is deliberately treated as hostile storage: it receives only
 * the ciphertext and nonce. The AES key is loaded from a host-only 0600 file
 * or an explicit environment variable and is never returned in a durable
 * binding or included in a log message.
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { closeSync, fstatSync, lstatSync, openSync, readFileSync, constants as fsConstants } from 'node:fs';

export const AGENT_CREDENTIAL_ALGORITHM = 'aes-256-gcm' as const;
export const AGENT_CREDENTIAL_NONCE_BYTES = 12;
export const AGENT_CREDENTIAL_TAG_BYTES = 16;

export interface EncryptedCredential {
  readonly ciphertext: Buffer;
  readonly nonce: Buffer;
}

function fail(message: string): never {
  throw new Error(`[agent-credentials] ${message}`);
}

function validateKey(key: Buffer): Buffer {
  if (!Buffer.isBuffer(key) || key.length !== 32) fail('master key must be exactly 32 bytes');
  return key;
}

/** Read a master key from an env value or an owner-only host file. */
export function loadCredentialMasterKey(options: {
  readonly env?: NodeJS.ProcessEnv;
  readonly envName?: string;
  readonly filePath?: string;
} = {}): Buffer {
  const env = options.env ?? process.env;
  const envName = options.envName ?? 'BOTMUX_AGENT_CREDENTIAL_MASTER_KEY';
  const raw = env[envName]?.trim();
  if (raw) {
    // Prefer base64url/base64, while accepting a 64-character hex key for
    // operators who keep secrets in the same format as other botmux keys.
    if (/^[0-9a-f]{64}$/iu.test(raw)) return validateKey(Buffer.from(raw, 'hex'));
    try { return validateKey(Buffer.from(raw, 'base64')); } catch { fail(`${envName} is not valid base64 or hex`); }
  }

  const filePath = options.filePath ?? env.BOTMUX_AGENT_CREDENTIAL_MASTER_KEY_FILE;
  if (!filePath) fail(`missing ${envName} or BOTMUX_AGENT_CREDENTIAL_MASTER_KEY_FILE`);
  let fd: number | undefined;
  try {
    const stat = lstatSync(filePath);
    if (!stat.isFile() || stat.isSymbolicLink()) fail('master key file must be a regular file');
    if ((stat.mode & 0o077) !== 0 || (stat.mode & 0o400) === 0) {
      fail('master key file must be owner-readable only (0600 or stricter)');
    }
    fd = openSync(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const opened = fstatSync(fd);
    if (!opened.isFile() || (opened.mode & 0o077) !== 0) fail('master key file changed during open');
    const contents = readFileSync(fd).toString('utf8').trim();
    if (/^[0-9a-f]{64}$/iu.test(contents)) return validateKey(Buffer.from(contents, 'hex'));
    try { return validateKey(Buffer.from(contents, 'base64')); } catch { fail('master key file is not valid base64 or hex'); }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('[agent-credentials]')) throw error;
    fail(`cannot read master key file: ${error instanceof Error ? error.message : String(error)}`);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
  fail('credential master key could not be loaded');
}

function aadForPrincipal(larkAppId: string, openId: string): Buffer {
  if (!larkAppId || !openId || /[\u0000\r\n]/u.test(larkAppId + openId)) {
    fail('principal key is invalid for credential encryption');
  }
  return Buffer.from(`botmux-agent-credential\0${larkAppId}\0${openId}`, 'utf8');
}

export function encryptCredential(
  plaintext: string | Buffer,
  masterKey: Buffer,
  principal: { readonly larkAppId: string; readonly openId: string },
): EncryptedCredential {
  const key = validateKey(masterKey);
  const nonce = randomBytes(AGENT_CREDENTIAL_NONCE_BYTES);
  const cipher = createCipheriv(AGENT_CREDENTIAL_ALGORITHM, key, nonce);
  cipher.setAAD(aadForPrincipal(principal.larkAppId, principal.openId));
  const body = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
  const ciphertext = Buffer.concat([cipher.update(body), cipher.final(), cipher.getAuthTag()]);
  return { ciphertext, nonce };
}

export function decryptCredential(
  encrypted: EncryptedCredential,
  masterKey: Buffer,
  principal: { readonly larkAppId: string; readonly openId: string },
): Buffer {
  const key = validateKey(masterKey);
  if (!Buffer.isBuffer(encrypted.nonce) || encrypted.nonce.length !== AGENT_CREDENTIAL_NONCE_BYTES) {
    fail('credential nonce has an invalid length');
  }
  if (!Buffer.isBuffer(encrypted.ciphertext) || encrypted.ciphertext.length < AGENT_CREDENTIAL_TAG_BYTES) {
    fail('credential ciphertext is truncated');
  }
  const tagOffset = encrypted.ciphertext.length - AGENT_CREDENTIAL_TAG_BYTES;
  const decipher = createDecipheriv(AGENT_CREDENTIAL_ALGORITHM, key, encrypted.nonce);
  decipher.setAAD(aadForPrincipal(principal.larkAppId, principal.openId));
  decipher.setAuthTag(encrypted.ciphertext.subarray(tagOffset));
  try {
    return Buffer.concat([decipher.update(encrypted.ciphertext.subarray(0, tagOffset)), decipher.final()]);
  } catch {
    fail('credential authentication failed');
  }
}

export function decryptCredentialUtf8(
  encrypted: EncryptedCredential,
  masterKey: Buffer,
  principal: { readonly larkAppId: string; readonly openId: string },
): string {
  return decryptCredential(encrypted, masterKey, principal).toString('utf8');
}

/** A non-reversible display fingerprint. Only the final four hex chars leave the host. */
export function credentialFingerprint(secret: string | Buffer): string {
  return createHash('sha256').update(secret).digest('hex').slice(-4);
}

/** Redact API keys/tokens from arbitrary error or CLI text before logging. */
export function redactCredentialText(value: unknown, secrets: readonly string[] = []): string {
  let text = value instanceof Error ? value.message : String(value);
  for (const secret of secrets) {
    if (secret.length >= 4) text = text.split(secret).join(`[redacted:${credentialFingerprint(secret)}]`);
  }
  return text
    .replace(/(api[_-]?key|access[_-]?token|refresh[_-]?token|authorization)(\s*[:=]\s*)([^\s,;]+)/giu, '$1$2[redacted]')
    .replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/giu, 'Bearer [redacted]');
}
