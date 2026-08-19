/**
 * Owner-only OpenMemory MCP bridge.
 *
 * The bridge is deliberately a very small host-side HTTP proxy.  It never
 * forwards the caller's headers wholesale: the only credential sent upstream
 * is the raw OM_API_KEY held by this process.  Containers receive a short-lived
 * capability, not that key, and the capability is bound to one principal and
 * one botmux session.
 */
import { createHash, createHmac, createSecretKey, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { lstatSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync, chmodSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { URL } from 'node:url';
import { parse as parseDotenv } from 'dotenv';

export const MEMORY_GATE_HOST = '127.0.0.1' as const;
export const MEMORY_GATE_PORT = 18181 as const;
export const MEMORY_GATE_UPSTREAM = 'http://127.0.0.1:8181/mcp' as const;
export const MEMORY_GATE_URL = 'http://127.0.0.1:18181/mcp' as const;
export const MEMORY_GATE_CAPABILITY_HEADER = 'x-botmux-memory-capability' as const;
export const MEMORY_GATE_CAPABILITY_ENV = 'BOTMUX_MEMORY_CAPABILITY' as const;
export const MEMORY_GATE_CAPABILITY_SECRET_ENV = 'BOTMUX_MEMORY_GATE_CAPABILITY_SECRET' as const;
export const MEMORY_GATE_RAW_KEY_ENV = 'OM_API_KEY' as const;
export const MEMORY_GATE_ENV_FILE = join(homedir(), '.botmux', '.env');
/** Dedicated authority file; unlike ~/.botmux/.env it contains only the signer. */
export const MEMORY_GATE_CAPABILITY_SECRET_FILE = join(homedir(), '.botmux', 'memory-gate-capability-secret');
export const MEMORY_GATE_CAPABILITY_TTL_MS = 5 * 60_000;
/** Sliding grace after the embedded expiry; activity cannot extend beyond hard max. */
export const MEMORY_GATE_CAPABILITY_SLIDING_WINDOW_MS = 5 * 60_000;
export const MEMORY_GATE_CAPABILITY_HARD_MAX_AFTER_EXPIRY_MS = 12 * 60 * 60_000;
export const MEMORY_GATE_READINESS_PATH = '/__botmux_memory_gate_ready' as const;
export const MEMORY_GATE_READINESS_FILE = join(homedir(), '.botmux', 'data', 'memory-gate-readiness.json');
export const MEMORY_GATE_READINESS_TTL_MS = 30_000;
export const MEMORY_GATE_READINESS_CLOCK_SKEW_MS = 5_000;
const MEMORY_GATE_READINESS_BODY_MAX_BYTES = 4_096;
const MEMORY_GATE_READINESS_PROBE_TIMEOUT_MS = 1_000;
const MEMORY_GATE_READINESS_HEARTBEAT_MS = 10_000;
export const MEMORY_GATE_MAX_BODY_BYTES = 1_048_576;
export const MEMORY_GATE_MAX_RESPONSE_BYTES = 8 * 1_048_576;
export const MEMORY_GATE_REQUEST_TIMEOUT_MS = 15_000;
export const MEMORY_GATE_HEADER_TIMEOUT_MS = 5_000;

const CAPABILITY_VERSION = 'v1';
const CAPABILITY_HASH_RE = /^[0-9a-f]{24}$/u;
const CAPABILITY_TOKEN_RE = /^v1\.([0-9]+)\.([0-9a-f]{24})\.([0-9a-f]{24})\.([0-9a-f]{32})\.([0-9a-f]{64})$/u;
const UPSTREAM = new URL(MEMORY_GATE_UPSTREAM);
const FORWARDED_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'x-api-key',
  'host',
  'forwarded',
  'via',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-port',
  'x-forwarded-proto',
  'x-real-ip',
  'cookie',
  'set-cookie',
]);

export interface MemoryGateCapabilityClaims {
  readonly sessionHash: string;
  readonly principalHash: string;
  readonly expiresAt: number;
  readonly nonce: string;
}

interface MemoryGateCapabilityRegistryEntry extends MemoryGateCapabilityClaims {
  readonly tokenHash: string;
  readonly hardExpiresAt: number;
  lastSeenAt: number;
}

export interface MemoryGatePrincipalBinding {
  readonly enabled?: boolean;
  readonly canOpenMemory?: boolean;
  readonly can_openmemory?: boolean;
}

export interface OwnerMemoryMcpConfig {
  readonly url: typeof MEMORY_GATE_URL;
  readonly capabilityEnvVar: typeof MEMORY_GATE_CAPABILITY_ENV;
  readonly capabilityHeader: typeof MEMORY_GATE_CAPABILITY_HEADER;
  readonly capability: string;
  readonly cliId: 'codex' | 'claude-code';
}

export interface MemoryGateSessionPlan {
  readonly capability: string;
  readonly mcp: OwnerMemoryMcpConfig;
}

function reject(message: string): never {
  throw new Error(`[memory-gate] ${message}`);
}

function hashPart(value: unknown, name: string): string {
  if (typeof value !== 'string' || !CAPABILITY_HASH_RE.test(value)) reject(`${name} must be a 24-character lowercase hash`);
  return value;
}

function capabilitySecret(secret: string | Buffer): Buffer {
  const value = Buffer.isBuffer(secret) ? Buffer.from(secret) : Buffer.from(secret, 'utf8');
  if (value.length < 32) reject('capability secret must be at least 32 bytes');
  return value;
}

export interface MemoryGateReadinessProof {
  readonly version: 'v1';
  readonly host: typeof MEMORY_GATE_HOST;
  readonly port: number;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly nonce: string;
  readonly signature: string;
}

function readinessPayload(proof: Pick<MemoryGateReadinessProof, 'version' | 'host' | 'port' | 'issuedAt' | 'expiresAt' | 'nonce'>): string {
  return `${proof.version}.${proof.host}.${proof.port}.${proof.issuedAt}.${proof.expiresAt}.${proof.nonce}`;
}

function readinessSignature(secret: string | Buffer, proof: Pick<MemoryGateReadinessProof, 'version' | 'host' | 'port' | 'issuedAt' | 'expiresAt' | 'nonce'>): string {
  return createHmac('sha256', createSecretKey(capabilitySecret(secret)))
    .update(readinessPayload(proof), 'utf8')
    .digest('hex');
}

function readinessPath(path?: string): string {
  return path ?? MEMORY_GATE_READINESS_FILE;
}

function validReadinessShape(value: unknown): value is MemoryGateReadinessProof {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const proof = value as Record<string, unknown>;
  return proof.version === 'v1'
    && proof.host === MEMORY_GATE_HOST
    && Number.isSafeInteger(proof.port) && (proof.port as number) >= 1 && (proof.port as number) <= 65_535
    && Number.isSafeInteger(proof.issuedAt) && Number.isSafeInteger(proof.expiresAt)
    && typeof proof.nonce === 'string' && /^[0-9a-f]{32}$/u.test(proof.nonce)
    && typeof proof.signature === 'string' && /^[0-9a-f]{64}$/u.test(proof.signature);
}

export function createMemoryGateReadinessProof(input: {
  readonly secret: string | Buffer;
  readonly port?: number;
  readonly nowMs?: number;
  readonly ttlMs?: number;
  readonly nonce?: string;
}): MemoryGateReadinessProof {
  const nowMs = input.nowMs ?? Date.now();
  const ttlMs = input.ttlMs ?? MEMORY_GATE_READINESS_TTL_MS;
  const port = input.port ?? MEMORY_GATE_PORT;
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || !Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > MEMORY_GATE_READINESS_TTL_MS) {
    reject('invalid readiness clock window');
  }
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) reject('invalid readiness port');
  const nonce = input.nonce ?? randomHex(16);
  if (!/^[0-9a-f]{32}$/u.test(nonce)) reject('invalid readiness nonce');
  const unsigned = {
    version: 'v1' as const,
    host: MEMORY_GATE_HOST,
    port,
    issuedAt: nowMs,
    expiresAt: nowMs + ttlMs,
    nonce,
  };
  return { ...unsigned, signature: readinessSignature(input.secret, unsigned) };
}

export function verifyMemoryGateReadinessProof(input: {
  readonly proof: unknown;
  readonly secret: string | Buffer;
  readonly nowMs?: number;
  readonly expectedPort?: number;
}): MemoryGateReadinessProof | undefined {
  if (!validReadinessShape(input.proof)) return undefined;
  const proof = input.proof;
  const nowMs = input.nowMs ?? Date.now();
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || (input.expectedPort !== undefined && proof.port !== input.expectedPort)) return undefined;
  if (proof.expiresAt <= proof.issuedAt || proof.expiresAt - proof.issuedAt > MEMORY_GATE_READINESS_TTL_MS) return undefined;
  if (proof.issuedAt > nowMs + MEMORY_GATE_READINESS_CLOCK_SKEW_MS
    || nowMs >= proof.expiresAt
    || nowMs - proof.issuedAt > MEMORY_GATE_READINESS_TTL_MS + MEMORY_GATE_READINESS_CLOCK_SKEW_MS) return undefined;
  const expected = Buffer.from(readinessSignature(input.secret, proof), 'hex');
  const supplied = Buffer.from(proof.signature, 'hex');
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return undefined;
  return proof;
}

export function writeMemoryGateReadiness(input: {
  readonly secret: string | Buffer;
  readonly path?: string;
  readonly port?: number;
  readonly nowMs?: number;
}): MemoryGateReadinessProof {
  const target = readinessPath(input.path);
  const proof = createMemoryGateReadinessProof(input);
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  const temp = `${target}.tmp-${process.pid}-${randomHex(8)}`;
  writeFileSync(temp, `${JSON.stringify(proof)}\n`, { mode: 0o600 });
  chmodSync(temp, 0o600);
  renameSync(temp, target);
  chmodSync(target, 0o600);
  return proof;
}

export function removeMemoryGateReadiness(path?: string): void {
  try { unlinkSync(readinessPath(path)); } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

function readMemoryGateReadiness(path?: string): unknown {
  const target = readinessPath(path);
  let stat: ReturnType<typeof lstatSync>;
  try { stat = lstatSync(target); } catch { return undefined; }
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || stat.size > MEMORY_GATE_READINESS_BODY_MAX_BYTES) return undefined;
  try { return JSON.parse(readFileSync(target, 'utf8')) as unknown; } catch { return undefined; }
}

export function readVerifiedMemoryGateReadiness(input: {
  readonly secret: string | Buffer;
  readonly path?: string;
  readonly nowMs?: number;
  readonly expectedPort?: number;
}): MemoryGateReadinessProof | undefined {
  return verifyMemoryGateReadinessProof({
    proof: readMemoryGateReadiness(input.path),
    secret: input.secret,
    nowMs: input.nowMs,
    expectedPort: input.expectedPort,
  });
}

function readReadinessHttpBody(input: {
  readonly port: number;
  readonly path: string;
  readonly timeoutMs: number;
}): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let total = 0;
    const chunks: Buffer[] = [];
    const finish = (error?: Error, value?: unknown): void => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };
    const req = httpRequest({
      host: MEMORY_GATE_HOST,
      port: input.port,
      method: 'GET',
      path: input.path,
      headers: { host: MEMORY_GATE_HOST, connection: 'close' },
      timeout: input.timeoutMs,
    }, res => {
      res.on('data', chunk => {
        const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        total += value.length;
        if (total > MEMORY_GATE_READINESS_BODY_MAX_BYTES) {
          res.destroy();
          finish(new Error('readiness_response_too_large'));
          return;
        }
        chunks.push(value);
      });
      res.once('error', error => finish(error));
      res.once('end', () => {
        if (res.statusCode !== 200) {
          finish(new Error('readiness_endpoint_unavailable'));
          return;
        }
        try { finish(undefined, JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown); } catch { finish(new Error('readiness_response_invalid')); }
      });
    });
    req.once('timeout', () => req.destroy(new Error('readiness_probe_timeout')));
    req.once('error', error => finish(error));
    req.end();
  });
}

/**
 * A capability signer must not mint merely because a secret exists in .env.
 * The dashboard gate proves both possession of the secret and ownership of
 * the fixed loopback listener through a short-lived file proof plus an HTTP
 * round trip to that listener.
 */
export async function probeMemoryGateReadiness(input: {
  readonly secret: string | Buffer;
  readonly path?: string;
  readonly expectedPort?: number;
  readonly nowMs?: number;
}): Promise<boolean> {
  const attempt = async (): Promise<boolean> => {
    const nowMs = input.nowMs ?? Date.now();
    const fileProof = readVerifiedMemoryGateReadiness({
      secret: input.secret,
      path: input.path,
      nowMs,
      expectedPort: input.expectedPort ?? MEMORY_GATE_PORT,
    });
    if (!fileProof) return false;
    try {
      const responseProof = await readReadinessHttpBody({
        port: fileProof.port,
        path: MEMORY_GATE_READINESS_PATH,
        timeoutMs: MEMORY_GATE_READINESS_PROBE_TIMEOUT_MS,
      });
      const verifiedResponse = verifyMemoryGateReadinessProof({
        proof: responseProof,
        secret: input.secret,
        nowMs,
        expectedPort: fileProof.port,
      });
      return verifiedResponse?.signature === fileProof.signature
        && verifiedResponse.nonce === fileProof.nonce
        && verifiedResponse.issuedAt === fileProof.issuedAt
        && verifiedResponse.expiresAt === fileProof.expiresAt;
    } catch {
      return false;
    }
  };
  // The gate heartbeat atomically replaces the proof file. A daemon can read
  // generation N and reach the HTTP endpoint after it has already published
  // generation N+1; retry one complete file+HTTP generation handshake before
  // failing closed, rather than treating that harmless boundary as outage.
  if (await attempt()) return true;
  return attempt();
}

function hmacForClaims(secret: Buffer, claims: MemoryGateCapabilityClaims): Buffer {
  return createHmac('sha256', createSecretKey(secret))
    .update(`${CAPABILITY_VERSION}.${claims.expiresAt}.${claims.sessionHash}.${claims.principalHash}.${claims.nonce}`, 'utf8')
    .digest();
}

/** Mint a compact, non-reversible capability for one session/principal pair. */
export function createMemoryGateCapability(input: {
  readonly secret: string | Buffer;
  readonly sessionHash: string;
  readonly principalHash: string;
  readonly nowMs?: number;
  readonly ttlMs?: number;
  readonly nonce?: string;
}): string {
  const sessionHash = hashPart(input.sessionHash, 'sessionHash');
  const principalHash = hashPart(input.principalHash, 'principalHash');
  const nowMs = input.nowMs ?? Date.now();
  const ttlMs = input.ttlMs ?? MEMORY_GATE_CAPABILITY_TTL_MS;
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) reject('nowMs must be a non-negative integer');
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 15 * 60_000) reject('ttlMs is outside the short capability window');
  const expiresAt = nowMs + ttlMs;
  if (!Number.isSafeInteger(expiresAt)) reject('capability expiry is outside the safe integer range');
  const nonce = input.nonce ?? randomHex(16);
  if (!/^[0-9a-f]{32}$/u.test(nonce)) reject('nonce must be 16 random bytes encoded as lowercase hex');
  const claims: MemoryGateCapabilityClaims = { sessionHash, principalHash, expiresAt, nonce };
  return `${CAPABILITY_VERSION}.${expiresAt}.${sessionHash}.${principalHash}.${nonce}.${hmacForClaims(capabilitySecret(input.secret), claims).toString('hex')}`;
}

function randomHex(bytes: number): string {
  // Avoid importing a second crypto helper into callers that only need the
  // deterministic verifier; randomUUID is not used because UUID formatting
  // would make the token needlessly distinguishable.
  return randomBytes(bytes).toString('hex');
}

/**
 * Verify a capability with a constant-time MAC comparison.  The returned
 * claims are only trusted after all session/principal/expiry checks pass.
 */
export function verifyMemoryGateCapability(input: {
  readonly token: string;
  readonly secret: string | Buffer;
  readonly sessionHash: string;
  readonly principalHash: string;
  readonly nowMs?: number;
  /** Internal gate registry grace; omitted callers retain strict expiry. */
  readonly allowExpiredUntilMs?: number;
}): MemoryGateCapabilityClaims | undefined {
  if (typeof input.token !== 'string' || input.token.length > 512) return undefined;
  const match = CAPABILITY_TOKEN_RE.exec(input.token);
  if (!match) return undefined;
  const [, expiryText, tokenSession, tokenPrincipal, nonce, signatureHex] = match;
  if (tokenSession !== input.sessionHash || tokenPrincipal !== input.principalHash) return undefined;
  if (!CAPABILITY_HASH_RE.test(input.sessionHash) || !CAPABILITY_HASH_RE.test(input.principalHash)) return undefined;
  const expiresAt = Number(expiryText);
  const nowMs = input.nowMs ?? Date.now();
  if (!Number.isSafeInteger(expiresAt) || !Number.isSafeInteger(nowMs)) return undefined;
  if (input.allowExpiredUntilMs !== undefined && !Number.isSafeInteger(input.allowExpiredUntilMs)) return undefined;
  if (nowMs >= expiresAt && (input.allowExpiredUntilMs === undefined || nowMs >= input.allowExpiredUntilMs)) return undefined;
  let expected: Buffer;
  try {
    expected = hmacForClaims(capabilitySecret(input.secret), {
      sessionHash: tokenSession,
      principalHash: tokenPrincipal,
      expiresAt,
      nonce,
    });
  } catch {
    return undefined;
  }
  const supplied = Buffer.from(signatureHex, 'hex');
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return undefined;
  return { sessionHash: tokenSession, principalHash: tokenPrincipal, expiresAt, nonce };
}

function capabilityTokenHash(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/**
 * Host-only sliding registry. The signed token remains the authority; the
 * registry only remembers that this exact token was successfully presented
 * before expiry, then permits an active owner to cross the short embedded
 * expiry. A bounded hard deadline prevents an active session from extending
 * a capability forever. Restarting the gate creates a fresh registry, so an
 * expired token cannot be revived across a process restart.
 */
export class MemoryGateCapabilityRegistry {
  private readonly entries = new Map<string, MemoryGateCapabilityRegistryEntry>();

  constructor(private readonly options: {
    readonly slidingWindowMs?: number;
    readonly hardMaxAfterExpiryMs?: number;
    readonly clock?: () => number;
  } = {}) {}

  accept(input: {
    readonly token: string;
    readonly secret: string | Buffer;
    readonly nowMs?: number;
  }): MemoryGateCapabilityClaims | undefined {
    const nowMs = input.nowMs ?? this.options.clock?.() ?? Date.now();
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) return undefined;
    for (const [staleHash, entry] of this.entries) {
      if (nowMs >= entry.hardExpiresAt) this.entries.delete(staleHash);
    }
    // A host daemon should not allow an unbounded number of owner launches to
    // turn the registry into a memory sink. This is an operational ceiling,
    // not an authorization decision; active entries are still HMAC checked.
    if (this.entries.size >= 4096) {
      const oldest = this.entries.keys().next().value;
      if (typeof oldest === 'string') this.entries.delete(oldest);
    }
    const tokenHash = capabilityTokenHash(input.token);
    const existing = this.entries.get(tokenHash);
    const match = CAPABILITY_TOKEN_RE.exec(input.token);
    if (!match) {
      this.entries.delete(tokenHash);
      return undefined;
    }
    const [, expiryText, tokenSession, tokenPrincipal] = match;
    const expiresAt = Number(expiryText);
    const hardMaxAfterExpiryMs = this.options.hardMaxAfterExpiryMs ?? MEMORY_GATE_CAPABILITY_HARD_MAX_AFTER_EXPIRY_MS;
    const slidingWindowMs = this.options.slidingWindowMs ?? MEMORY_GATE_CAPABILITY_SLIDING_WINDOW_MS;
    const hardExpiresAt = expiresAt + hardMaxAfterExpiryMs;
    if (!Number.isSafeInteger(expiresAt) || !Number.isSafeInteger(hardExpiresAt) || !Number.isSafeInteger(hardMaxAfterExpiryMs)
      || hardMaxAfterExpiryMs < 1_000 || !Number.isSafeInteger(slidingWindowMs) || slidingWindowMs < 1_000) {
      this.entries.delete(tokenHash);
      return undefined;
    }
    const claims = verifyMemoryGateCapability({
      token: input.token,
      secret: input.secret,
      sessionHash: tokenSession,
      principalHash: tokenPrincipal,
      nowMs,
      ...(existing ? { allowExpiredUntilMs: existing.hardExpiresAt } : {}),
    });
    if (!claims) {
      this.entries.delete(tokenHash);
      return undefined;
    }
    if (!existing) {
      this.entries.set(tokenHash, {
        ...claims,
        tokenHash,
        hardExpiresAt,
        lastSeenAt: nowMs,
      });
      return claims;
    }
    if (existing.sessionHash !== claims.sessionHash || existing.principalHash !== claims.principalHash
      || existing.expiresAt !== claims.expiresAt || existing.nonce !== claims.nonce
      || nowMs >= existing.hardExpiresAt
      || (nowMs >= claims.expiresAt && nowMs >= existing.lastSeenAt + slidingWindowMs)) {
      this.entries.delete(tokenHash);
      return undefined;
    }
    existing.lastSeenAt = nowMs;
    return claims;
  }

  clear(): void {
    this.entries.clear();
  }

  get size(): number { return this.entries.size; }
}

function strictCanOpenMemory(binding: MemoryGatePrincipalBinding): boolean {
  if (binding.enabled !== true) return false;
  const camel = binding.canOpenMemory;
  const snake = binding.can_openmemory;
  if (camel !== undefined && typeof camel !== 'boolean') return false;
  if (snake !== undefined && typeof snake !== 'boolean') return false;
  if (camel !== undefined && snake !== undefined && camel !== snake) return false;
  return camel === true || snake === true;
}

/**
 * Only Codex and Claude have a known remote-HTTP MCP configuration contract in
 * this build. Pi/OpenCode deliberately return no plan instead of guessing a
 * config file or CLI flag.
 */
export function supportsOwnerMemoryMcp(cliId: string): cliId is 'codex' | 'claude-code' {
  return cliId === 'codex' || cliId === 'claude-code';
}

/** Build the owner-only capability/config plan without writing a file. */
export function buildOwnerMemoryGatePlan(input: {
  readonly principal: MemoryGatePrincipalBinding;
  readonly cliId: string;
  readonly sessionHash: string;
  readonly principalHash: string;
  readonly capabilitySecret?: string | Buffer;
  readonly nowMs?: number;
  readonly ttlMs?: number;
}): MemoryGateSessionPlan | undefined {
  if (!strictCanOpenMemory(input.principal)) return undefined;
  if (!supportsOwnerMemoryMcp(input.cliId)) reject('owner OpenMemory MCP is unsupported by this harness');
  if (!input.capabilitySecret) reject('owner OpenMemory capability secret is not configured');
  const capability = createMemoryGateCapability({
    secret: input.capabilitySecret,
    sessionHash: input.sessionHash,
    principalHash: input.principalHash,
    nowMs: input.nowMs,
    ttlMs: input.ttlMs,
  });
  return {
    capability,
    mcp: {
      url: MEMORY_GATE_URL,
      capabilityEnvVar: MEMORY_GATE_CAPABILITY_ENV,
      capabilityHeader: MEMORY_GATE_CAPABILITY_HEADER,
      capability,
      cliId: input.cliId,
    },
  };
}

/**
 * Rehydrate the non-secret config half at the Podman launch boundary.  The
 * HMAC is checked by MemoryGate itself; this host-side check only prevents a
 * stale token from being attached to a different runtime path before launch.
 */
export function buildOwnerMemoryGatePlanFromCapability(input: {
  readonly principal: MemoryGatePrincipalBinding;
  readonly cliId: string;
  readonly sessionHash: string;
  readonly principalHash: string;
  readonly capability: string;
  readonly nowMs?: number;
}): MemoryGateSessionPlan | undefined {
  if (!strictCanOpenMemory(input.principal)) return undefined;
  if (!supportsOwnerMemoryMcp(input.cliId)) reject('owner OpenMemory MCP is unsupported by this harness');
  const parsed = CAPABILITY_TOKEN_RE.exec(input.capability);
  if (!parsed) reject('owner OpenMemory capability has an invalid shape');
  const [, expiryText, tokenSession, tokenPrincipal] = parsed;
  const nowMs = input.nowMs ?? Date.now();
  if (tokenSession !== input.sessionHash || tokenPrincipal !== input.principalHash
    || !Number.isSafeInteger(nowMs) || nowMs < 0
    || !Number.isSafeInteger(Number(expiryText)) || nowMs >= Number(expiryText)) {
    reject('owner OpenMemory capability is stale or bound to another runtime');
  }
  return {
    capability: input.capability,
    mcp: {
      url: MEMORY_GATE_URL,
      capabilityEnvVar: MEMORY_GATE_CAPABILITY_ENV,
      capabilityHeader: MEMORY_GATE_CAPABILITY_HEADER,
      capability: input.capability,
      cliId: input.cliId,
    },
  };
}

export function loadMemoryGateCapabilitySecret(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const value = env[MEMORY_GATE_CAPABILITY_SECRET_ENV]?.trim();
  return value && Buffer.byteLength(value, 'utf8') >= 32 ? value : undefined;
}

export function loadMemoryGateRawApiKey(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const value = env[MEMORY_GATE_RAW_KEY_ENV];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function readSecureMemoryGateEnvFile(envFilePath: string): Record<string, string> {
  let stat: ReturnType<typeof lstatSync>;
  try { stat = lstatSync(envFilePath); } catch { return {}; }
  // The dashboard reads this file only for the raw OM_API_KEY. Refuse
  // symlinks and group/world-readable files at that boundary as well.
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) return {};
  try { return parseDotenv(readFileSync(envFilePath, 'utf8')); } catch { return {}; }
}

function readMemoryGateCapabilitySecretFile(secretFilePath: string): string | undefined {
  let stat: ReturnType<typeof lstatSync>;
  try { stat = lstatSync(secretFilePath); } catch { return undefined; }
  // This file is deliberately separate from ~/.botmux/.env: a daemon can
  // read this one value without ever parsing or materialising Lark/API/raw OM
  // credentials in its process. It is owner-only and never follows symlinks.
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0 || stat.size > 4_096) return undefined;
  let value: string;
  try { value = readFileSync(secretFilePath, 'utf8').trim(); } catch { return undefined; }
  if (!value || /[\u0000\r\n]/u.test(value)) return undefined;
  return Buffer.byteLength(value, 'utf8') >= 32 ? value : undefined;
}

/** Read only the capability signer from its dedicated private file. */
export function loadMemoryGateCapabilitySecretFromConfig(
  secretFilePath: string = MEMORY_GATE_CAPABILITY_SECRET_FILE,
): string | undefined {
  return readMemoryGateCapabilitySecretFile(secretFilePath);
}

/**
 * Resolve gate-only secrets without baking either secret into PM2's generated
 * ecosystem file. Dashboard is the sole caller in production; daemons read
 * the signer through the narrow permission-checked config helper above.
 */
export function loadMemoryGateRuntimeEnv(
  env: NodeJS.ProcessEnv = process.env,
  envFilePath: string = MEMORY_GATE_ENV_FILE,
  capabilitySecretFilePath: string = MEMORY_GATE_CAPABILITY_SECRET_FILE,
): NodeJS.ProcessEnv {
  const fileEnv = readSecureMemoryGateEnvFile(envFilePath);
  const rawApiKey = env[MEMORY_GATE_RAW_KEY_ENV]?.trim() || fileEnv[MEMORY_GATE_RAW_KEY_ENV]?.trim() || '';
  const capabilitySecret = loadMemoryGateCapabilitySecretFromConfig(capabilitySecretFilePath) || '';
  return {
    ...env,
    // These values live only in the gate host's in-memory env snapshot.
    [MEMORY_GATE_RAW_KEY_ENV]: rawApiKey,
    [MEMORY_GATE_CAPABILITY_SECRET_ENV]: capabilitySecret,
  };
}

function responseJson(res: ServerResponse, status: number, body: { readonly error: string }): void {
  const payload = Buffer.from(JSON.stringify(body), 'utf8');
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.setHeader('content-length', payload.length);
  res.end(payload);
}

function capabilityFromHeaders(req: IncomingMessage): string | undefined {
  const raw = req.headers[MEMORY_GATE_CAPABILITY_HEADER];
  if (Array.isArray(raw)) return undefined;
  if (typeof raw === 'string') return raw;
  // Codex's supported remote-MCP contract emits `Authorization: Bearer` when
  // configured with bearer_token_env_var. Treat it as the same non-raw
  // capability channel; it is still stripped before the upstream request.
  const authorization = req.headers.authorization;
  if (Array.isArray(authorization) || typeof authorization !== 'string') return undefined;
  const match = /^Bearer ([^\s]+)$/u.exec(authorization);
  return match?.[1];
}

class MemoryGateRequestBodyError extends Error {
  constructor(readonly code: 'body_too_large' | 'body_timeout' | 'body_aborted') {
    super(code);
  }
}

async function readRequestBodyWithTimeout(
  req: IncomingMessage,
  maxBytes: number,
  timeoutMs: number,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks: Buffer[] = [];
    let settled = false;
    const timer = setTimeout(() => fail(new MemoryGateRequestBodyError('body_timeout')), timeoutMs);
    const cleanup = (): void => {
      clearTimeout(timer);
      req.off('data', onData);
      req.off('end', onEnd);
      req.off('aborted', onAborted);
      req.off('error', onError);
    };
    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      // Stop reading attacker-controlled bytes while the 408/413 response is
      // still being written. The socket is closed only after res.finish.
      req.pause();
      reject(error);
    };
    const onData = (chunk: Buffer | string): void => {
      const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += value.length;
      if (total > maxBytes) {
        fail(new MemoryGateRequestBodyError('body_too_large'));
        return;
      }
      chunks.push(value);
    };
    const onEnd = (): void => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(Buffer.concat(chunks));
    };
    const onAborted = (): void => fail(new MemoryGateRequestBodyError('body_aborted'));
    const onError = (): void => fail(new MemoryGateRequestBodyError('body_aborted'));
    req.on('data', onData);
    req.once('end', onEnd);
    req.once('aborted', onAborted);
    req.once('error', onError);
  });
}

function respondAndCloseRequest(
  req: IncomingMessage,
  res: ServerResponse,
  status: number,
  body: { readonly error: string },
): void {
  req.pause();
  // The body reader deliberately detaches its error listener before this
  // response path. Keep a sink attached until the request socket is closed so
  // the final destroy cannot become an unhandled IncomingMessage error.
  req.on('error', () => {});
  res.setHeader('connection', 'close');
  const closeRequest = (): void => {
    try { req.destroy(); } catch { /* already closed */ }
  };
  res.once('finish', closeRequest);
  res.once('close', closeRequest);
  responseJson(res, status, body);
}

function allowedRequestHeaders(req: IncomingMessage): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [name, raw] of Object.entries(req.headers)) {
    const lower = name.toLowerCase();
    if (FORWARDED_HEADERS.has(lower) || lower === MEMORY_GATE_CAPABILITY_HEADER) continue;
    if (lower !== 'content-type' && lower !== 'accept' && lower !== 'content-length'
      && lower !== 'mcp-session-id' && lower !== 'last-event-id') continue;
    if (Array.isArray(raw) || raw === undefined) continue;
    headers[lower] = raw;
  }
  // The upstream OpenMemory MCP endpoint expects JSON and no connection
  // reuse. Setting these explicitly also prevents Node's agent from adding a
  // host/forwarded header derived from the caller.
  headers.host = UPSTREAM.host;
  headers.connection = 'close';
  return headers;
}

function proxyMcpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  body: Buffer,
  rawApiKey: string,
  timeoutMs = MEMORY_GATE_REQUEST_TIMEOUT_MS,
): void {
  const headers = allowedRequestHeaders(req);
  headers['content-length'] = String(body.length);
  headers['x-api-key'] = rawApiKey;
  const upstream = httpRequest({
    protocol: UPSTREAM.protocol,
    hostname: UPSTREAM.hostname,
    port: UPSTREAM.port,
    method: 'POST',
    path: UPSTREAM.pathname,
    headers,
    timeout: timeoutMs,
  }, upstreamRes => {
    let total = 0;
    const chunks: Buffer[] = [];
    let responseTooLarge = false;
    let responseFinished = false;
    upstreamRes.on('data', (chunk: Buffer | string) => {
      if (responseTooLarge) return;
      const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += value.length;
      if (total > MEMORY_GATE_MAX_RESPONSE_BYTES) {
        responseTooLarge = true;
        // Keep the error listener below attached before destroying the stream;
        // otherwise Node reports the deliberate limit error as unhandled.
        upstreamRes.destroy(new Error('upstream_response_too_large'));
        return;
      }
      chunks.push(value);
    });
    upstreamRes.once('error', () => {
      if (!responseFinished && !res.headersSent) responseJson(res, 502, { error: 'memory_upstream_unavailable' });
    });
    upstreamRes.on('end', () => {
      if (responseFinished || res.headersSent || responseTooLarge) return;
      responseFinished = true;
      const response = redactRawApiKey(Buffer.concat(chunks), rawApiKey);
      res.statusCode = upstreamRes.statusCode && upstreamRes.statusCode >= 100
        ? upstreamRes.statusCode
        : 502;
      const contentType = upstreamRes.headers['content-type'];
      if (typeof contentType === 'string') res.setHeader('content-type', contentType);
      res.setHeader('content-length', response.length);
      res.end(response);
    });
  });
  upstream.setTimeout(timeoutMs, () => upstream.destroy(new Error('upstream_timeout')));
  upstream.once('error', () => {
    if (!res.headersSent) responseJson(res, 502, { error: 'memory_upstream_unavailable' });
    else res.destroy();
  });
  upstream.end(body);
}

/** Defense in depth: a misbehaving upstream must not echo the host key back. */
function redactRawApiKey(payload: Buffer, rawApiKey: string): Buffer {
  if (!rawApiKey) return payload;
  const text = payload.toString('utf8');
  if (!text.includes(rawApiKey)) return payload;
  return Buffer.from(text.split(rawApiKey).join('[REDACTED]'), 'utf8');
}

export interface MemoryGateServerOptions {
  readonly rawApiKey: string;
  readonly capabilitySecret: string | Buffer;
  readonly host?: typeof MEMORY_GATE_HOST;
  readonly port?: typeof MEMORY_GATE_PORT;
  /** Test-only seam; production callers must use the fixed 18181 listener. */
  readonly testOnlyPort?: number;
  /** Test-only proof path; production always uses ~/.botmux/data/... */
  readonly testOnlyReadinessPath?: string;
  readonly maxBodyBytes?: number;
  readonly requestTimeoutMs?: number;
  /** Injectable clock keeps sliding-expiry tests deterministic. */
  readonly clock?: () => number;
}

/** A repeat-start-safe owner-only proxy server. */
export class MemoryGateServer {
  private server: Server | undefined;
  private startPromise: Promise<void> | undefined;
  private readinessTimer: ReturnType<typeof setInterval> | undefined;
  private readinessProof: MemoryGateReadinessProof | undefined;
  private readonly capabilityRegistry: MemoryGateCapabilityRegistry;

  constructor(private readonly options: MemoryGateServerOptions) {
    if (!options.rawApiKey) reject('raw OpenMemory API key is required');
    if (/[\u0000\r\n]/u.test(options.rawApiKey)) reject('raw OpenMemory API key contains an invalid control character');
    capabilitySecret(options.capabilitySecret);
    if (options.host !== undefined && options.host !== MEMORY_GATE_HOST) reject('host must be 127.0.0.1');
    if (options.port !== undefined && options.port !== MEMORY_GATE_PORT) reject('port must be 18181');
    if (options.testOnlyPort !== undefined
      && (!Number.isSafeInteger(options.testOnlyPort) || options.testOnlyPort < 0 || options.testOnlyPort > 65_535)) {
      reject('invalid test-only port');
    }
    this.capabilityRegistry = new MemoryGateCapabilityRegistry({ clock: options.clock });
  }

  get listening(): boolean { return this.server?.listening === true; }
  get boundPort(): number | undefined {
    const address = this.server?.address();
    return address && typeof address === 'object' ? address.port : undefined;
  }

  private get readinessFile(): string | undefined { return this.options.testOnlyReadinessPath; }

  private writeReadinessProof(): void {
    const port = this.boundPort;
    if (!port) reject('memory gate did not expose a bound loopback port');
    this.readinessProof = writeMemoryGateReadiness({
      secret: this.options.capabilitySecret,
      path: this.readinessFile,
      port,
      nowMs: this.options.clock?.() ?? Date.now(),
    });
  }

  private clearReadiness(): void {
    if (this.readinessTimer !== undefined) clearInterval(this.readinessTimer);
    this.readinessTimer = undefined;
    this.readinessProof = undefined;
    try { removeMemoryGateReadiness(this.readinessFile); } catch { /* best effort during shutdown */ }
  }

  async start(): Promise<void> {
    if (this.server?.listening) return;
    if (this.startPromise) return this.startPromise;
    const maxBodyBytes = this.options.maxBodyBytes ?? MEMORY_GATE_MAX_BODY_BYTES;
    const timeoutMs = this.options.requestTimeoutMs ?? MEMORY_GATE_REQUEST_TIMEOUT_MS;
    if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1 || maxBodyBytes > MEMORY_GATE_MAX_BODY_BYTES) reject('invalid body limit');
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > MEMORY_GATE_REQUEST_TIMEOUT_MS) reject('invalid timeout');
    const server = createServer((req, res) => {
      void this.handle(req, res, maxBodyBytes, timeoutMs);
    });
    server.headersTimeout = MEMORY_GATE_HEADER_TIMEOUT_MS;
    server.requestTimeout = timeoutMs;
    this.startPromise = new Promise<void>((resolve, rejectStart) => {
      const onError = (error: Error): void => {
        server.off('listening', onListening);
        rejectStart(error);
      };
      const onListening = (): void => {
        server.off('error', onError);
        this.server = server;
        try {
          this.writeReadinessProof();
          this.readinessTimer = setInterval(() => {
            if (!this.server?.listening) return;
            try { this.writeReadinessProof(); } catch { /* readiness probe will fail closed */ }
          }, MEMORY_GATE_READINESS_HEARTBEAT_MS);
          this.readinessTimer.unref?.();
          resolve();
        } catch (error) {
          this.server = undefined;
          this.clearReadiness();
          try { server.close(); } catch { /* already closed */ }
          rejectStart(error);
        }
      };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen(this.options.testOnlyPort ?? this.options.port ?? MEMORY_GATE_PORT, this.options.host ?? MEMORY_GATE_HOST);
    }).finally(() => { this.startPromise = undefined; });
    try {
      await this.startPromise;
    } catch (error) {
      try { server.close(); } catch { /* already closed */ }
      throw error;
    }
  }

  private async handle(req: IncomingMessage, res: ServerResponse, maxBodyBytes: number, timeoutMs: number): Promise<void> {
    res.setHeader('cache-control', 'no-store');
    if (req.url === MEMORY_GATE_READINESS_PATH) {
      if (req.method !== 'GET') {
        responseJson(res, 405, { error: 'method_not_allowed' });
        return;
      }
      if (!this.readinessProof) {
        responseJson(res, 503, { error: 'memory_gate_not_ready' });
        return;
      }
      const payload = Buffer.from(`${JSON.stringify(this.readinessProof)}\n`, 'utf8');
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.setHeader('content-length', payload.length);
      res.end(payload);
      return;
    }
    if (req.url !== '/mcp') {
      responseJson(res, 404, { error: 'not_found' });
      return;
    }
    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      res.end();
      return;
    }
    if (req.method !== 'POST') {
      responseJson(res, 405, { error: 'method_not_allowed' });
      return;
    }
    const contentType = req.headers['content-type'];
    if (typeof contentType !== 'string' || !/^application\/json(?:\s*;|\s*$)/iu.test(contentType)) {
      responseJson(res, 415, { error: 'mcp_json_required' });
      return;
    }
    const capability = capabilityFromHeaders(req);
    if (!capability) {
      responseJson(res, 401, { error: 'memory_capability_required' });
      return;
    }
    // The capability carries its own session/principal hashes.  The bridge
    // does not accept user-provided identity headers, which prevents a caller
    // from changing the binding after verification.
    if (!this.capabilityRegistry.accept({
      token: capability,
      secret: this.options.capabilitySecret,
    })) {
      responseJson(res, 403, { error: 'memory_capability_invalid' });
      return;
    }
    const contentLength = req.headers['content-length'];
    if (typeof contentLength === 'string') {
      const length = Number(contentLength);
      if (!Number.isSafeInteger(length) || length < 0 || length > maxBodyBytes) {
        respondAndCloseRequest(req, res, 413, { error: 'memory_body_too_large' });
        return;
      }
    }
    let body: Buffer;
    try {
      body = await readRequestBodyWithTimeout(req, maxBodyBytes, timeoutMs);
    } catch (error) {
      const code = error instanceof MemoryGateRequestBodyError ? error.code : 'body_aborted';
      if (code === 'body_too_large') respondAndCloseRequest(req, res, 413, { error: 'memory_body_too_large' });
      else respondAndCloseRequest(req, res, 408, { error: 'memory_request_timeout' });
      return;
    }
    proxyMcpRequest(req, res, body, this.options.rawApiKey, timeoutMs);
  }

  async stop(): Promise<void> {
    const server = this.server;
    this.server = undefined;
    this.clearReadiness();
    this.capabilityRegistry.clear();
    if (!server) return;
    await new Promise<void>(resolve => server.close(() => resolve()));
  }

  stopSync(): void {
    const server = this.server;
    this.server = undefined;
    this.clearReadiness();
    this.capabilityRegistry.clear();
    try { server?.close(); } catch { /* best effort during process exit */ }
  }
}

let processGate: MemoryGateServer | undefined;

/** Start the host gate when both host-only secrets are present. */
export async function ensureMemoryGateFromEnv(
  env: NodeJS.ProcessEnv = process.env,
  testOnlyOptions?: Pick<MemoryGateServerOptions, 'testOnlyPort' | 'testOnlyReadinessPath'> & { readonly testOnlyCapabilitySecret?: string | Buffer },
): Promise<MemoryGateServer | undefined> {
  const rawApiKey = loadMemoryGateRawApiKey(env);
  // The dashboard and daemon both use the dedicated signer file in runtime.
  // A secret override exists only on the explicitly test-only seam; the
  // legacy env name remains available to one-time migration tooling, but is
  // never a production fallback that would reintroduce broad env exposure.
  const capabilitySecret = testOnlyOptions?.testOnlyCapabilitySecret
    ?? loadMemoryGateCapabilitySecretFromConfig();
  if (!rawApiKey || !capabilitySecret) return undefined;
  if (processGate?.listening) return processGate;
  const { testOnlyCapabilitySecret: _testOnlyCapabilitySecret, ...serverOptions } = testOnlyOptions ?? {};
  const candidate = new MemoryGateServer({ rawApiKey, capabilitySecret, ...serverOptions });
  try {
    await candidate.start();
  } catch (error) {
    // The dashboard is the sole owner. A listener on 18181 is never silently
    // adopted: an EADDRINUSE is an operational failure and owner sessions
    // must remain fail-closed until the real dashboard gate is healthy.
    throw error;
  }
  processGate = candidate;
  return candidate;
}

export async function stopMemoryGate(): Promise<void> {
  const gate = processGate;
  processGate = undefined;
  await gate?.stop();
}

export function stopMemoryGateSync(): void {
  const gate = processGate;
  processGate = undefined;
  gate?.stopSync();
}

export function __testOnly_resetMemoryGate(): void {
  processGate?.stopSync();
  processGate = undefined;
}
