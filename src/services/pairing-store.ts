/**
 * Pairing-login store: binds a browser session to a Feishu user without a web
 * OAuth redirect (which is unfriendly to ip:port self-host — see
 * docs/platform-design.md). Device-code style:
 *
 *   1. Browser (unauthenticated) calls start → gets a short human `code` to show
 *      the user, plus a high-entropy `browserToken` it keeps privately.
 *   2. User sends the `code` to the bot in Feishu. The daemon (which already
 *      knows the sender's open_id) claims the pairing for that identity.
 *   3. Browser polls/consumes with its `browserToken`; on a claimed pairing it
 *      learns the Feishu identity and the web endpoint issues a session.
 *
 * Identity is established INSIDE Feishu, so only a short-lived code crosses to
 * the web — independent of domain/IP/port. Team-membership gating is the
 * caller's job (via team-store); this store only pairs browser ↔ identity.
 *
 * Security: code is high-entropy + short TTL + single-use; browserToken gates
 * status/consume so a guessed code alone can't hijack a browser session.
 * (Brute-forcing codes is further bounded by endpoint rate limiting at the wiring
 * layer.) Codes/tokens are never logged.
 *
 * Storage: `{dataDir}/pairings.json` (shared across the web + daemon processes),
 * atomic writes.
 */
import {
  readFileSync, writeFileSync, mkdirSync, renameSync,
  lstatSync, chmodSync, unlinkSync, rmSync,
} from 'node:fs';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';

const DEFAULT_TTL_MS = 5 * 60 * 1000; // 5 minutes
/** Unambiguous alphabet (no 0/O/1/I) for the human-entered code. */
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const CODE_LEN = 8;
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const STORE_LOCK_STALE_MS = 30_000;
const STORE_LOCK_WAIT_MS = 5_000;

/** A public start endpoint can reject capacity without exposing store errors. */
export class PairingCapacityError extends Error {
  readonly code = 'pairing_capacity';

  constructor() {
    super('pairing capacity reached');
    this.name = 'PairingCapacityError';
  }
}

export type PairingStatus = 'pending' | 'claimed' | 'consumed';

export interface PairingClaimer {
  openId: string;
  unionId?: string;
  name?: string;
  /** The bot app the user ran `/pair` with — open_id is scoped to THIS app. */
  larkAppId?: string;
}

interface PairingEntry {
  pairingId: string;
  code: string;
  browserToken: string;
  status: PairingStatus;
  createdAt: number;
  expiresAt: number;
  claimedBy?: PairingClaimer;
}

interface PairingSessionEntry {
  readonly sessionToken: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly principal: PairingClaimer;
  revokedAt?: number;
}

type FileShape = Record<string, PairingEntry>; // keyed by pairingId
type SessionFileShape = Record<string, PairingSessionEntry>; // keyed by session token

function filePath(dataDir: string): string {
  return join(dataDir, 'pairings.json');
}

function sessionsFilePath(dataDir: string): string {
  return join(dataDir, 'pairing-sessions.json');
}

function hasPath(path: string): boolean {
  try { lstatSync(path); return true; }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}

function ensureSecureDirectory(dataDir: string): void {
  if (hasPath(dataDir)) {
    const stat = lstatSync(dataDir);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('pairing data directory is not a trusted directory');
  } else {
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  }
  chmodSync(dataDir, 0o700);
}

function assertRegularFile(path: string): void {
  if (!hasPath(path)) return;
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('pairing storage must be a regular file');
}

function sleepSync(milliseconds: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

/** Serialize JSON RMW operations across dashboard and daemon processes. */
function acquireStoreLock(dataDir: string, scope: 'pairings' | 'sessions'): () => void {
  ensureSecureDirectory(dataDir);
  const lockPath = join(dataDir, `.${scope}.lock`);
  const ownerPath = join(lockPath, 'owner');
  const owner = randomUUID();
  const deadline = Date.now() + STORE_LOCK_WAIT_MS;
  while (true) {
    try {
      mkdirSync(lockPath, { mode: 0o700 });
      chmodSync(lockPath, 0o700);
      writeFileSync(ownerPath, owner + '\n', { encoding: 'utf8', mode: 0o600, flag: 'wx' });
      chmodSync(ownerPath, 0o600);
      return () => {
        try {
          const lockStat = lstatSync(lockPath);
          const ownerStat = lstatSync(ownerPath);
          if (!lockStat.isDirectory() || lockStat.isSymbolicLink()
            || !ownerStat.isFile() || ownerStat.isSymbolicLink()
            || readFileSync(ownerPath, 'utf8') !== `${owner}\n`) return;
          rmSync(lockPath, { recursive: true, force: false });
        } catch { /* another process recovered a stale lock */ }
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      try {
        const stat = lstatSync(lockPath);
        if (!stat.isDirectory() || stat.isSymbolicLink()) {
          throw new Error('pairing store lock is not a trusted directory');
        }
        // mkdir is atomic, but another process may be between mkdir and its
        // chmod. Give that tiny publication window a bounded retry; a stable
        // wrong-mode lock remains a hard failure rather than being repaired.
        if ((stat.mode & 0o777) !== 0o700) {
          if (Date.now() - stat.mtimeMs < 100) { sleepSync(10); continue; }
          throw new Error('pairing store lock is not a trusted directory');
        }
        if (Date.now() - stat.mtimeMs > STORE_LOCK_STALE_MS) {
          rmSync(lockPath, { recursive: true, force: false });
          continue;
        }
      } catch (lockError) {
        if ((lockError as NodeJS.ErrnoException).code !== 'ENOENT') throw lockError;
        continue;
      }
      if (Date.now() >= deadline) throw new Error('pairing store is busy');
      sleepSync(10);
    }
  }
}

function withStoreLock<T>(dataDir: string, scope: 'pairings' | 'sessions', fn: () => T): T {
  const release = acquireStoreLock(dataDir, scope);
  try { return fn(); } finally { release(); }
}

function readFile(dataDir: string): FileShape {
  ensureSecureDirectory(dataDir);
  const fp = filePath(dataDir);
  if (!hasPath(fp)) return {};
  assertRegularFile(fp);
  chmodSync(fp, 0o600);
  try {
    const parsed = JSON.parse(readFileSync(fp, 'utf-8'));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed as FileShape;
  } catch { /* corrupt — fall through */ }
  return {};
}

function readSessions(dataDir: string): SessionFileShape {
  ensureSecureDirectory(dataDir);
  const fp = sessionsFilePath(dataDir);
  if (!hasPath(fp)) return {};
  assertRegularFile(fp);
  chmodSync(fp, 0o600);
  try {
    const parsed = JSON.parse(readFileSync(fp, 'utf-8'));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed as SessionFileShape;
  } catch { /* corrupt — fail closed for all sessions */ }
  return {};
}

function writeFileAtomic(dataDir: string, data: FileShape): void {
  ensureSecureDirectory(dataDir);
  const fp = filePath(dataDir);
  assertRegularFile(fp);
  const tmp = `${fp}.${process.pid}.${randomUUID()}.tmp`;
  try {
    writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', { encoding: 'utf-8', mode: 0o600, flag: 'wx' });
    chmodSync(tmp, 0o600);
    renameSync(tmp, fp);
    chmodSync(fp, 0o600);
  } finally {
    try { unlinkIfExists(tmp); } catch { /* best effort cleanup */ }
  }
}

function writeSessionsAtomic(dataDir: string, data: SessionFileShape): void {
  ensureSecureDirectory(dataDir);
  const fp = sessionsFilePath(dataDir);
  assertRegularFile(fp);
  const tmp = `${fp}.${process.pid}.${randomUUID()}.tmp`;
  try {
    writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', { encoding: 'utf-8', mode: 0o600, flag: 'wx' });
    chmodSync(tmp, 0o600);
    renameSync(tmp, fp);
    chmodSync(fp, 0o600);
  } finally {
    unlinkIfExists(tmp);
  }
}

function unlinkIfExists(path: string): void {
  try {
    unlinkSync(path);
  } catch { /* absent */ }
}

/** Drop expired entries; returns the live map. */
function prune(data: FileShape, now: number): FileShape {
  for (const [id, e] of Object.entries(data)) {
    if (e.expiresAt <= now) delete data[id];
  }
  return data;
}

function genCode(): string {
  const bytes = randomBytes(CODE_LEN);
  let out = '';
  for (let i = 0; i < CODE_LEN; i++) out += CODE_ALPHABET[bytes[i] % CODE_ALPHABET.length];
  return out;
}

export interface StartedPairing {
  pairingId: string;
  code: string;
  browserToken: string;
  expiresAt: number;
}

/** Begin a pairing. Returns the code to show the user + a private browserToken. */
export function createPairing(
  dataDir: string,
  ttlMs: number = DEFAULT_TTL_MS,
  now: number = Date.now(),
  maxLivePairings: number = Number.POSITIVE_INFINITY,
): StartedPairing {
  return withStoreLock(dataDir, 'pairings', () => {
    const data = prune(readFile(dataDir), now);
    const liveCount = Object.values(data).filter(entry =>
      entry.expiresAt > now && (entry.status === 'pending' || entry.status === 'claimed'),
    ).length;
    if (liveCount >= maxLivePairings) throw new PairingCapacityError();
    const entry: PairingEntry = {
      pairingId: randomUUID(),
      code: genCode(),
      browserToken: randomBytes(24).toString('base64url'),
      status: 'pending',
      createdAt: now,
      expiresAt: now + ttlMs,
    };
    data[entry.pairingId] = entry;
    writeFileAtomic(dataDir, data);
    return { pairingId: entry.pairingId, code: entry.code, browserToken: entry.browserToken, expiresAt: entry.expiresAt };
  });
}

export type ClaimResult =
  | { ok: true; pairingId: string }
  | { ok: false; reason: 'not_found' | 'expired' | 'already_claimed' };

/** Claim a pending pairing for a Feishu identity (called by the daemon on the bot side). */
export function claimPairing(dataDir: string, code: string, claimer: PairingClaimer, now: number = Date.now()): ClaimResult {
  return withStoreLock(dataDir, 'pairings', () => {
    const data = prune(readFile(dataDir), now);
    const entry = Object.values(data).find(e => e.code === code.trim().toUpperCase());
    if (!entry) return { ok: false, reason: 'not_found' };
    if (entry.expiresAt <= now) return { ok: false, reason: 'expired' };
    if (entry.status !== 'pending') return { ok: false, reason: 'already_claimed' };
    entry.status = 'claimed';
    entry.claimedBy = {
      openId: claimer.openId,
      ...(claimer.unionId ? { unionId: claimer.unionId } : {}),
      ...(claimer.name ? { name: claimer.name } : {}),
      ...(claimer.larkAppId ? { larkAppId: claimer.larkAppId } : {}),
    };
    writeFileAtomic(dataDir, data);
    return { ok: true, pairingId: entry.pairingId };
  });
}

export type PairingView =
  | { status: 'pending' }
  | { status: 'claimed'; claimedBy: PairingClaimer }
  | { status: 'consumed' }
  | { status: 'not_found' };

/** Browser-side status poll; requires the matching browserToken. */
export function getPairingStatus(dataDir: string, pairingId: string, browserToken: string, now: number = Date.now()): PairingView {
  const data = prune(readFile(dataDir), now);
  const entry = data[pairingId];
  if (!entry || entry.browserToken !== browserToken) return { status: 'not_found' };
  if (entry.status === 'claimed' && entry.claimedBy) return { status: 'claimed', claimedBy: entry.claimedBy };
  if (entry.status === 'consumed') return { status: 'consumed' };
  return { status: 'pending' };
}

export type ConsumeResult =
  | { ok: true; claimedBy: PairingClaimer }
  | { ok: false; reason: 'not_found' | 'not_claimed' | 'already_consumed' };

/** Single-use: turn a claimed pairing into a session. Requires the browserToken. */
export function consumePairing(dataDir: string, pairingId: string, browserToken: string, now: number = Date.now()): ConsumeResult {
  return withStoreLock(dataDir, 'pairings', () => {
    const data = prune(readFile(dataDir), now);
    const entry = data[pairingId];
    if (!entry || entry.browserToken !== browserToken) return { ok: false, reason: 'not_found' };
    if (entry.status === 'consumed') return { ok: false, reason: 'already_consumed' };
    if (entry.status !== 'claimed' || !entry.claimedBy) return { ok: false, reason: 'not_claimed' };
    entry.status = 'consumed';
    const claimedBy = entry.claimedBy;
    writeFileAtomic(dataDir, data);
    return { ok: true, claimedBy };
  });
}

/** Resolve the identity bound to a browser pairing session. The browserToken
 * remains the bearer credential after consume; callers must never accept an
 * open_id from JSON when this helper is available. */
export function getConsumedPairingPrincipal(
  dataDir: string,
  pairingId: string,
  browserToken: string,
  now: number = Date.now(),
): PairingClaimer | undefined {
  const data = prune(readFile(dataDir), now);
  const entry = data[pairingId];
  if (!entry || entry.browserToken !== browserToken || entry.status !== 'consumed' || !entry.claimedBy) return undefined;
  return { ...entry.claimedBy };
}

export interface AgentPairingSession {
  readonly sessionToken: string;
  readonly expiresAt: number;
  readonly principal: PairingClaimer;
}

function pruneSessions(data: SessionFileShape, now: number): SessionFileShape {
  for (const [token, entry] of Object.entries(data)) {
    if (!entry || entry.expiresAt <= now || entry.revokedAt !== undefined) delete data[token];
  }
  return data;
}

/** Convert a consumed browser pairing into a revocable, longer-lived session. */
export function createAgentPairingSession(
  dataDir: string,
  principal: PairingClaimer,
  ttlMs: number = SESSION_TTL_MS,
  now: number = Date.now(),
): AgentPairingSession {
  if (!principal.larkAppId || !principal.openId) throw new TypeError('pairing principal must be app-scoped');
  return withStoreLock(dataDir, 'sessions', () => {
    const data = pruneSessions(readSessions(dataDir), now);
    const sessionToken = randomBytes(32).toString('base64url');
    const entry: PairingSessionEntry = {
      sessionToken,
      createdAt: now,
      expiresAt: now + ttlMs,
      principal: { ...principal },
    };
    data[sessionToken] = entry;
    writeSessionsAtomic(dataDir, data);
    return { sessionToken, expiresAt: entry.expiresAt, principal: { ...entry.principal } };
  });
}

/** Resolve a bearer session. Expired/revoked sessions are indistinguishable. */
export function getAgentPairingSession(
  dataDir: string,
  sessionToken: string,
  now: number = Date.now(),
): AgentPairingSession | undefined {
  if (typeof sessionToken !== 'string' || sessionToken.length < 32) return undefined;
  const data = pruneSessions(readSessions(dataDir), now);
  const entry = data[sessionToken];
  if (!entry || entry.expiresAt <= now || entry.revokedAt !== undefined) return undefined;
  // Reads stay side-effect free. In particular, writing a pruned snapshot here
  // could race a concurrent revoke and resurrect the revoked token. Expiry is
  // checked on every lookup; create/revoke operations perform persistence.
  return { sessionToken: entry.sessionToken, expiresAt: entry.expiresAt, principal: { ...entry.principal } };
}

/** Revoke a browser session; repeated revocation is deliberately idempotent. */
export function revokeAgentPairingSession(dataDir: string, sessionToken: string, now: number = Date.now()): boolean {
  return withStoreLock(dataDir, 'sessions', () => {
    const data = pruneSessions(readSessions(dataDir), now);
    if (!data[sessionToken]) {
      writeSessionsAtomic(dataDir, data);
      return false;
    }
    delete data[sessionToken];
    writeSessionsAtomic(dataDir, data);
    return true;
  });
}
