/** Validation shared by the credential page, CLI seed helpers, and repository. */
import { isIP } from 'node:net';
import { lookup } from 'node:dns/promises';

export interface ApiCredentialInput {
  readonly key: string;
  readonly baseUrl: string;
  readonly model: string;
}

function invalid(message: string): never { throw new TypeError(`[agent-credentials] ${message}`); }

function isPrivateIpv4(value: string): boolean {
  const parts = value.split('.').map(Number);
  if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = parts;
  return a === 0 || a === 10 || a === 127 || a >= 224
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 0)
    || (a === 192 && b === 168)
    || (a === 198 && (b === 18 || b === 19));
}

function isPrivateIpv6(value: string): boolean {
  const lower = value.toLowerCase();
  if (lower.startsWith('::ffff:')) return isPrivateIpv4(lower.slice('::ffff:'.length));
  return lower === '::' || lower === '::1' || lower.startsWith('fc') || lower.startsWith('fd')
    || lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')
    || lower.startsWith('ff') || lower.startsWith('2001:db8:');
}

export function isReservedAddress(host: string): boolean {
  const normalized = host.replace(/^\[|\]$/g, '').toLowerCase();
  if (normalized === 'localhost' || normalized.endsWith('.localhost') || normalized === 'localhost.localdomain') return true;
  const family = isIP(normalized);
  return family === 4 ? isPrivateIpv4(normalized) : family === 6 ? isPrivateIpv6(normalized) : false;
}

export function validateBaseUrl(baseUrl: string): URL {
  if (typeof baseUrl !== 'string' || baseUrl.trim() === '') invalid('BaseURL is required');
  let parsed: URL;
  try { parsed = new URL(baseUrl.trim()); } catch { invalid('BaseURL must be a valid URL'); }
  if (parsed.protocol !== 'https:') invalid('BaseURL must use HTTPS');
  if (parsed.username || parsed.password) invalid('BaseURL must not contain userinfo');
  if (!parsed.hostname || isReservedAddress(parsed.hostname)) invalid('BaseURL may not target localhost or a reserved address');
  // The path is provider-specific, but URL fragments are never sent to a
  // server and are commonly accidental secret-bearing copy/paste material.
  if (parsed.hash || parsed.search) invalid('BaseURL must not contain a query or fragment');
  return parsed;
}

/** Synchronous checks used before an encrypted upsert. */
export function validateApiCredentialInput(input: ApiCredentialInput): { key: string; baseUrl: URL; model: string; fingerprint: string } {
  if (typeof input.key !== 'string' || input.key.trim() === '' || /[\u0000\r\n]/u.test(input.key)) invalid('API key is required');
  if (input.key.length > 4096) invalid('API key is too long');
  const baseUrl = validateBaseUrl(input.baseUrl);
  if (typeof input.model !== 'string' || input.model.trim() === '' || /[\u0000\r\n]/u.test(input.model)) invalid('model is required');
  if (input.model.trim().length > 256) invalid('model is too long');
  // Deliberately avoid importing crypto here: the repository computes the
  // display fingerprint from the exact secret bytes it encrypts.
  return { key: input.key, baseUrl, model: input.model.trim(), fingerprint: '' };
}

/** Resolve DNS and reject a hostname that lands in a private/reserved range. */
export async function validateApiCredentialEndpoint(baseUrl: string, resolver = lookup): Promise<URL> {
  const parsed = validateBaseUrl(baseUrl);
  const addresses = await resolver(parsed.hostname, { all: true, verbatim: true });
  if (!Array.isArray(addresses) || addresses.length === 0) invalid('BaseURL hostname did not resolve');
  if (addresses.some(address => isReservedAddress(address.address))) {
    invalid('BaseURL resolves to a localhost, private, link-local, or reserved address');
  }
  return parsed;
}
