/** Host-side relay for data-lake publish requests emitted by a sandbox. */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  chmodSync, closeSync, constants as fsConstants, existsSync, fstatSync,
  fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync,
  readSync, renameSync, rmSync, statSync, unlinkSync, writeFileSync, writeSync,
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';

export const DATA_PUBLISH_CAPABILITY_BASENAME = '.botmux-data-publish-capability.json';
export const DATA_PUBLISH_REQUEST_PREFIX = 'publish-';
/** Host-only sibling of the child-writable outbox. */
export const DATA_PUBLISH_SNAPSHOT_DIRNAME = '.botmux-data-publish-snapshots';
/**
 * T3 writes the sha256 idempotency key as the request filename.  Keep the
 * original botmux helper format accepted as well so old images can be drained
 * during a rolling upgrade, but do not accept arbitrary filenames from the
 * writable outbox.
 */
const DATA_PUBLISH_REQUEST_RE = /^(?:publish-[a-f0-9]{32}|[a-f0-9]{64})\.json$/u;
const MAX_REQUEST_BYTES = 64 * 1024;
const MAX_STAGING_FILE_BYTES = 256 * 1024 * 1024;
const O_NOFOLLOW = fsConstants.O_NOFOLLOW ?? 0;
const O_DIRECTORY = fsConstants.O_DIRECTORY ?? 0;

export interface DataPublishCapability {
  readonly sessionId: string;
  readonly capability: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  /** Optional turn binding added by the worker for T3's envelope check. */
  readonly turnId?: string;
  readonly dispatchAttempt?: number;
}

export interface DataPublishRequest {
  readonly requestId: string;
  readonly datasetId: string;
  readonly stagingRelativePath: string;
  readonly capability: string;
  /** These are intentionally not accepted from an untrusted writer. */
  readonly sessionId?: never;
  readonly ownerOpenId?: never;
  readonly stagingDir?: never;
}

export interface ValidatedDataPublishRequest {
  readonly requestId: string;
  /** T3's request filename identity (the 64-char idempotency key). */
  readonly idempotencyKey?: string;
  readonly datasetId: string;
  readonly stagingPath: string;
  /** Host-local immutable snapshot selected by the watcher. Never supplied by the child. */
  readonly requestPath: string;
  /** Host-only directory containing requestPath. */
  readonly snapshotRoot: string;
  /** Host-only private staging root retained for the queued publication job. */
  readonly stagingSnapshotRoot: string;
  /** The copied staging request directory/file under stagingSnapshotRoot. */
  readonly stagingSnapshotPath: string;
  /** Capability copied only into the in-memory host callback envelope. */
  readonly capability: string;
  readonly sessionId: string;
  readonly sessionHash?: string;
  readonly ownerOpenIdHash?: string;
  readonly payloadHash?: string;
  readonly baseVersionHash?: string;
  readonly requestedPartitions?: readonly string[];
  readonly partitionBaseHashes?: Readonly<Record<string, string>>;
  readonly source?: readonly string[];
  readonly turnId?: string;
}

function fail(message: string): never { throw new Error(`[data-relay] ${message}`); }

function safeToken(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{32,128}$/iu.test(value)) fail('invalid capability');
  return value;
}

function safeSessionId(value: unknown): string {
  if (typeof value !== 'string' || value.trim() === '' || /[\u0000\r\n]/u.test(value) || value.length > 256) fail('invalid session id');
  return value.trim();
}

function safeDatasetId(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(value)) fail('invalid dataset id');
  return value;
}

function safeEnvelopeText(value: unknown, name: string, maxLength = 256): string {
  if (typeof value !== 'string' || value.trim() === '' || value.length > maxLength
    || /[\u0000\r\n]/u.test(value)) fail(`invalid ${name}`);
  return value.trim();
}

function safeHash(value: unknown, name: string): string {
  const hash = safeEnvelopeText(value, name, 128);
  if (!/^[a-f0-9]{24,128}$/u.test(hash)) fail(`invalid ${name}`);
  return hash;
}

function safeTurnId(value: unknown): string {
  return safeEnvelopeText(value, 'turn id', 256);
}

function safeStringList(value: unknown, name: string): readonly string[] {
  if (!Array.isArray(value) || value.length > 1024) fail(`invalid ${name}`);
  return value.map(item => safeEnvelopeText(item, name, 256));
}

function safePartitionBaseHashes(value: unknown): Readonly<Record<string, string>> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('invalid partition base hashes');
  const output: Record<string, string> = {};
  for (const [partition, hash] of Object.entries(value)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*=[^/\\]+$/u.test(partition)) fail('invalid partition base hash key');
    output[partition] = safeHash(hash, 'partition base hash');
  }
  return output;
}

function safeRelativePath(value: unknown): string {
  if (typeof value !== 'string' || value.trim() === '' || value.includes('\0') || value.includes('\\') || isAbsolute(value)) {
    fail('stagingRelativePath must be a relative POSIX path');
  }
  const normalized = value.trim();
  const parts = normalized.split('/');
  if (parts.some(part => part === '' || part === '.' || part === '..')) fail('stagingRelativePath contains traversal');
  return normalized;
}

function equalCapability(left: string, right: string): boolean {
  const a = Buffer.from(left, 'utf8');
  const b = Buffer.from(right, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

function ensurePrivateDirectory(dir: string): void {
  try {
    const existing = lstatSync(dir);
    if (!existing.isDirectory() || existing.isSymbolicLink()) fail(`relay directory is not a real directory: ${dir}`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  chmodSync(dir, 0o700);
  const stat = lstatSync(dir);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`relay directory is not a real directory: ${dir}`);
}

function atomicWrite(path: string, body: string): void {
  const tmp = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
  writeFileSync(tmp, body, { encoding: 'utf8', mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
}

function isWithin(parent: string, candidate: string): boolean {
  const rel = relative(parent, candidate);
  return rel === '' || (!isAbsolute(rel) && rel !== '..' && !rel.startsWith('../'));
}

/**
 * Derive the host-only snapshot location. It is deliberately a sibling, never
 * the child mount itself or a directory below that mount.
 */
export function dataPublishSnapshotRoot(outboxRoot: string): string {
  const outbox = resolve(outboxRoot);
  const snapshotRoot = resolve(dirname(outbox), DATA_PUBLISH_SNAPSHOT_DIRNAME);
  if (snapshotRoot === outbox || isWithin(outbox, snapshotRoot) || isWithin(snapshotRoot, outbox)) {
    fail('data publish snapshot directory must be a sibling of the outbox');
  }
  return snapshotRoot;
}

function isLinuxMountPoint(path: string): boolean {
  if (process.platform !== 'linux') return false;
  try {
    const target = resolve(path);
    return readFileSync('/proc/self/mountinfo', 'utf8').split('\n').some(line => {
      const fields = line.split(' - ', 1)[0]?.split(' ') ?? [];
      const mountPoint = fields[4]
        ?.replaceAll('\\040', ' ')
        .replaceAll('\\011', '\t')
        .replaceAll('\\134', '\\');
      return mountPoint !== undefined && resolve(mountPoint) === target;
    });
  } catch {
    return false;
  }
}

function ensureHostSnapshotDirectory(outboxRoot: string): string {
  const outbox = resolve(outboxRoot);
  const outboxStat = lstatSync(outbox);
  if (!outboxStat.isDirectory() || outboxStat.isSymbolicLink()) fail('outbox must be a real directory');
  const parent = dirname(outbox);
  const parentStat = lstatSync(parent);
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) fail('outbox parent must be a real directory');
  const snapshotRoot = dataPublishSnapshotRoot(outbox);
  try {
    const existing = lstatSync(snapshotRoot);
    if (!existing.isDirectory() || existing.isSymbolicLink()) {
      fail('data publish snapshot directory is not a real directory');
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    mkdirSync(snapshotRoot, { mode: 0o700 });
  }
  chmodSync(snapshotRoot, 0o700);
  const snapshotStat = lstatSync(snapshotRoot);
  if (!snapshotStat.isDirectory() || snapshotStat.isSymbolicLink()) {
    fail('data publish snapshot directory is not a real directory');
  }
  if (isLinuxMountPoint(snapshotRoot)) fail('data publish snapshot directory may not be a mount point');
  return snapshotRoot;
}

function writeRequestSnapshot(snapshotRoot: string, sourceName: string, body: string): string {
  const snapshotPath = join(
    snapshotRoot,
    `${sourceName}.${process.pid}.${randomBytes(16).toString('hex')}.json`,
  );
  atomicWrite(snapshotPath, body);
  const stat = lstatSync(snapshotPath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_REQUEST_BYTES) {
    try { unlinkSync(snapshotPath); } catch { /* best effort */ }
    fail('data publish snapshot is not a regular file');
  }
  chmodSync(snapshotPath, 0o600);
  return snapshotPath;
}

function readDirectoryEntries(fd: number, fallback: string): string[] {
  // A proc fd pins the directory inode while a child-owned staging tree is
  // being copied. This prevents a concurrent replacement of the parent path
  // from redirecting the walk to an arbitrary host directory.
  if (process.platform === 'linux') return readdirSync(`/proc/self/fd/${fd}`);
  return readdirSync(fallback);
}

function sourceChildPath(fd: number, parent: string, name: string): string {
  return process.platform === 'linux' ? `/proc/self/fd/${fd}/${name}` : join(parent, name);
}

function copyRegularFile(source: string, destination: string): void {
  let sourceFd: number | undefined;
  let destinationFd: number | undefined;
  const temporary = `${destination}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
  try {
    sourceFd = openSync(source, fsConstants.O_RDONLY | O_NOFOLLOW);
    const sourceStat = fstatSync(sourceFd);
    if (!sourceStat.isFile() || sourceStat.isSymbolicLink() || sourceStat.size > MAX_STAGING_FILE_BYTES) {
      fail('staging payload contains a non-regular or oversized file');
    }
    mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
    destinationFd = openSync(
      temporary,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | O_NOFOLLOW,
      0o600,
    );
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let copied = 0;
    while (true) {
      const read = readSync(sourceFd, buffer, 0, buffer.length, null);
      if (read === 0) break;
      copied += read;
      if (copied > MAX_STAGING_FILE_BYTES) fail('staging payload is oversized');
      let offset = 0;
      while (offset < read) offset += writeSync(destinationFd, buffer, offset, read - offset, null);
    }
    fsyncSync(destinationFd);
    closeSync(destinationFd);
    destinationFd = undefined;
    chmodSync(temporary, 0o600);
    renameSync(temporary, destination);
  } catch (error) {
    try { unlinkSync(temporary); } catch { /* best effort */ }
    throw error;
  } finally {
    if (destinationFd !== undefined) closeSync(destinationFd);
    if (sourceFd !== undefined) closeSync(sourceFd);
  }
}

function copyStagingEntry(source: string, destination: string): void {
  let sourceFd: number | undefined;
  try {
    const sourceStat = lstatSync(source);
    if (sourceStat.isSymbolicLink()) fail('staging payload may not use symlinks');
    if (sourceStat.isDirectory()) {
      sourceFd = openSync(source, fsConstants.O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
      // A T3 staging path may contain turn/request components.  Create only
      // real private parents before copying the pinned directory inode.
      mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
      mkdirSync(destination, { recursive: false, mode: 0o700 });
      chmodSync(destination, 0o700);
      for (const name of readDirectoryEntries(sourceFd, source)) {
        copyStagingEntry(sourceChildPath(sourceFd, source, name), join(destination, name));
      }
      return;
    }
    if (!sourceStat.isFile()) fail('staging payload contains a special file');
    copyRegularFile(source, destination);
  } finally {
    if (sourceFd !== undefined) closeSync(sourceFd);
  }
}

function hashRegularFile(path: string): string {
  let fd: number | undefined;
  try {
    fd = openSync(path, fsConstants.O_RDONLY | O_NOFOLLOW);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_STAGING_FILE_BYTES) {
      fail('staging snapshot contains a non-regular or oversized file');
    }
    const digest = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    while (true) {
      const read = readSync(fd, buffer, 0, buffer.length, null);
      if (read === 0) break;
      digest.update(buffer.subarray(0, read));
    }
    return digest.digest('hex');
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function payloadFiles(root: string): string[] {
  const payloadRoot = join(root, 'payload');
  const stat = lstatSync(payloadRoot);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail('staging snapshot payload directory is missing');
  const files: string[] = [];
  const walk = (directory: string): void => {
    for (const name of readdirSync(directory)) {
      const path = join(directory, name);
      const child = lstatSync(path);
      if (child.isSymbolicLink()) fail('staging snapshot payload may not use symlinks');
      if (child.isDirectory()) walk(path);
      else if (child.isFile()) files.push(path);
      else fail('staging snapshot payload contains a special file');
    }
  };
  walk(payloadRoot);
  if (files.length === 0) fail('staging snapshot payload is empty');
  return files.sort();
}

function computePayloadHash(root: string): string {
  const files = payloadFiles(root);
  if (files.length === 1) return hashRegularFile(files[0]!);
  const entries = files.map(path => {
    const stat = lstatSync(path);
    return [relative(root, path).split('\\').join('/'), stat.size, hashRegularFile(path)];
  });
  return createHash('sha256').update(JSON.stringify(entries)).digest('hex');
}

function createStagingSnapshot(input: {
  readonly snapshotRoot: string;
  readonly sourceRoot: string;
  readonly sourcePath: string;
  readonly requestId: string;
  readonly payloadHash?: string;
}): { readonly root: string; readonly path: string } {
  const sourceRoot = resolve(input.sourceRoot);
  const sourcePath = resolve(input.sourcePath);
  const rel = relative(sourceRoot, sourcePath);
  if (!rel || rel === '..' || rel.startsWith('../') || isAbsolute(rel)) fail('staging snapshot source escapes session');
  const jobsRoot = join(input.snapshotRoot, 'staging-jobs');
  ensurePrivateDirectory(jobsRoot);
  const root = join(jobsRoot, `${input.requestId}.${randomBytes(12).toString('hex')}`);
  mkdirSync(root, { recursive: false, mode: 0o700 });
  try {
    copyStagingEntry(sourcePath, join(root, rel));
    // qlib requires an explicit host-private marker when it inserts the job.
    atomicWrite(join(root, '.botmux-private-staging'), 'botmux-private-staging-v1\n');
    const copiedPath = join(root, rel);
    if (input.payloadHash && lstatSync(copiedPath).isDirectory()) {
      if (computePayloadHash(copiedPath) !== input.payloadHash) fail('staging payload hash changed during snapshot');
    }
    return { root, path: copiedPath };
  } catch (error) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
    throw error;
  }
}

export function createDataPublishCapability(
  sessionId: string,
  ttlMs = 5 * 60_000,
  now = Date.now(),
  envelope?: { readonly turnId?: string; readonly dispatchAttempt?: number },
): DataPublishCapability {
  if (envelope?.turnId !== undefined) safeTurnId(envelope.turnId);
  if (envelope?.dispatchAttempt !== undefined
    && (!Number.isSafeInteger(envelope.dispatchAttempt) || envelope.dispatchAttempt < 0)) {
    fail('invalid dispatch attempt');
  }
  return {
    sessionId: safeSessionId(sessionId),
    capability: randomBytes(32).toString('hex'),
    issuedAt: now,
    expiresAt: now + Math.max(1_000, Math.min(ttlMs, 15 * 60_000)),
    ...(envelope?.turnId !== undefined ? { turnId: envelope.turnId } : {}),
    ...(envelope?.dispatchAttempt !== undefined ? { dispatchAttempt: envelope.dispatchAttempt } : {}),
  };
}

export function publishDataCapability(outboxRoot: string, claim: DataPublishCapability): string {
  ensurePrivateDirectory(outboxRoot);
  const path = join(outboxRoot, DATA_PUBLISH_CAPABILITY_BASENAME);
  atomicWrite(path, JSON.stringify(claim) + '\n');
  return path;
}

/** Read the child-visible hint for diagnostics/CLI only. Host authorization
 * must use the in-memory capability callback supplied to DataPublishRelay. */
export function readDataPublishCapability(outboxRoot: string, now = Date.now()): DataPublishCapability | undefined {
  const path = join(outboxRoot, DATA_PUBLISH_CAPABILITY_BASENAME);
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4096) return undefined;
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
    const claim: DataPublishCapability = {
      sessionId: safeSessionId(parsed.sessionId),
      capability: safeToken(parsed.capability),
      issuedAt: Number(parsed.issuedAt),
      expiresAt: Number(parsed.expiresAt),
      ...(parsed.turnId !== undefined ? { turnId: safeTurnId(parsed.turnId) } : {}),
      ...(parsed.dispatchAttempt !== undefined
        ? { dispatchAttempt: Number(parsed.dispatchAttempt) }
        : {}),
    };
    if (!Number.isFinite(claim.issuedAt) || !Number.isFinite(claim.expiresAt)
      || claim.expiresAt <= now
      || claim.dispatchAttempt !== undefined
        && (!Number.isSafeInteger(claim.dispatchAttempt) || claim.dispatchAttempt < 0)) return undefined;
    return claim;
  } catch { return undefined; }
}

/** Validate and derive every host path from the current session, never input. */
export function validateDataPublishRequest(input: {
  readonly raw: unknown;
  readonly outboxRoot: string;
  readonly currentSessionId: string;
  readonly sessionStagingRoot: string;
  readonly currentCapability: DataPublishCapability;
  /** Host-derived identity for rich T3 envelopes. */
  readonly expectedSessionHash?: string;
  readonly expectedOwnerOpenIdHash?: string;
  /** Filename identity; required by the watcher and optional for direct unit use. */
  readonly requestFileName?: string;
  readonly now?: number;
}): Omit<ValidatedDataPublishRequest, 'stagingSnapshotRoot' | 'stagingSnapshotPath'> {
  if (!input.raw || typeof input.raw !== 'object' || Array.isArray(input.raw)) fail('request must be an object');
  const raw = input.raw as Record<string, unknown>;
  const isT3 = raw.kind === 'lake_publish_request' || raw.version === 1 || raw.request_id !== undefined;
  const allowed = isT3
    ? [
        'version', 'kind', 'request_id', 'dataset_id', 'staging_path', 'session_hash',
        'owner_open_id_hash', 'payload_hash', 'base_version_hash', 'requested_partitions',
        'partition_base_hashes', 'idempotency_key', 'source', 'capability', 'turn_id',
        'created_at',
      ]
    : ['requestId', 'datasetId', 'stagingRelativePath', 'capability'];
  const unknown = Object.keys(raw).filter(key => !allowed.includes(key));
  if (unknown.length > 0) fail('request contains forbidden identity/path fields');
  if (isT3 && (raw.version !== 1 || raw.kind !== 'lake_publish_request')) {
    fail('unsupported data publish request version');
  }
  const requestId = isT3 ? safeEnvelopeText(raw.request_id, 'request id', 128) : raw.requestId;
  if (typeof requestId !== 'string' || !/^[a-f0-9-]{32,128}$/iu.test(requestId)) fail('invalid request id');
  const datasetId = safeDatasetId(isT3 ? raw.dataset_id : raw.datasetId);
  const stagingRelativePath = safeRelativePath(isT3 ? raw.staging_path : raw.stagingRelativePath);
  const capability = safeToken(raw.capability);
  const sessionId = safeSessionId(input.currentSessionId);
  if (input.currentCapability.sessionId !== sessionId || input.currentCapability.expiresAt <= (input.now ?? Date.now())) {
    fail('session capability is stale');
  }
  if (!equalCapability(capability, input.currentCapability.capability)) fail('capability is stale or forged');
  const turnId = isT3 ? safeTurnId(raw.turn_id) : undefined;
  if (isT3 && (!turnId || !input.currentCapability.turnId || turnId !== input.currentCapability.turnId)) {
    fail('turn capability is stale or forged');
  }
  const sessionHash = isT3 ? safeHash(raw.session_hash, 'session hash') : undefined;
  const ownerOpenIdHash = isT3 ? safeHash(raw.owner_open_id_hash, 'owner hash') : undefined;
  const payloadHash = isT3 ? safeHash(raw.payload_hash, 'payload hash') : undefined;
  const baseVersionHash = isT3 ? safeHash(raw.base_version_hash, 'base version hash') : undefined;
  const requestedPartitions = isT3 ? safeStringList(raw.requested_partitions, 'requested partitions') : undefined;
  const partitionBaseHashes = isT3 ? safePartitionBaseHashes(raw.partition_base_hashes) : undefined;
  const source = isT3 ? safeStringList(raw.source, 'source') : undefined;
  const idempotencyKey = isT3 ? safeHash(raw.idempotency_key, 'idempotency key') : undefined;
  if (isT3) {
    if (!input.expectedSessionHash || !input.expectedOwnerOpenIdHash) {
      fail('host session identity is unavailable');
    }
    if (sessionHash !== input.expectedSessionHash) fail('session hash does not match the current session');
    if (ownerOpenIdHash !== input.expectedOwnerOpenIdHash) fail('owner hash does not match the current session');
  }
  if (input.requestFileName) {
    const filename = input.requestFileName;
    if (!DATA_PUBLISH_REQUEST_RE.test(filename)) fail('invalid request filename');
    const filenameKey = filename.endsWith('.json') ? filename.slice(0, -'.json'.length) : filename;
    if (isT3) {
      if (idempotencyKey !== filenameKey) fail('idempotency key does not match its filename');
    } else if (requestId !== filenameKey.slice(DATA_PUBLISH_REQUEST_PREFIX.length)) {
      fail('request id does not match its filename');
    }
  }
  const stagingRoot = resolve(input.sessionStagingRoot);
  const stagingPath = resolve(stagingRoot, stagingRelativePath);
  const rel = relative(stagingRoot, stagingPath);
  if (!rel || rel === '..' || rel.startsWith('../') || isAbsolute(rel)) fail('staging path escapes current session');
  const outbox = resolve(input.outboxRoot);
  const snapshotRoot = dataPublishSnapshotRoot(outbox);
  const requestPath = resolve(outbox, input.requestFileName ?? `${requestId}.json`);
  if (!requestPath.startsWith(`${outbox}/`)) fail('request path escapes outbox');
  // stagingPath is intentionally returned only after canonical containment;
  // callers still need to lstat/reject symlinks before opening it.
  return {
    requestId,
    ...(idempotencyKey ? { idempotencyKey } : {}),
    datasetId,
    stagingPath,
    requestPath,
    snapshotRoot,
    capability,
    sessionId,
    ...(sessionHash ? { sessionHash } : {}),
    ...(ownerOpenIdHash ? { ownerOpenIdHash } : {}),
    ...(payloadHash ? { payloadHash } : {}),
    ...(baseVersionHash ? { baseVersionHash } : {}),
    ...(requestedPartitions ? { requestedPartitions } : {}),
    ...(partitionBaseHashes ? { partitionBaseHashes } : {}),
    ...(source ? { source } : {}),
    ...(turnId ? { turnId } : {}),
  };
}

function readDataPublishRequestFile(path: string): { readonly raw: unknown; readonly body: string } {
  let fd: number | undefined;
  try {
    // Read through one no-following descriptor. The descriptor pins the inode
    // that was validated, so a child cannot swap the pathname while JSON is
    // being parsed or while the host snapshot is being written.
    fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_REQUEST_BYTES) {
      fail('request file must be a small regular file');
    }
    const body = readFileSync(fd, 'utf8');
    return { raw: JSON.parse(body) as unknown, body };
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

export function parseDataPublishRequestFile(path: string): unknown {
  return readDataPublishRequestFile(path).raw;
}

/** Verify the derived staging target before a trusted publisher opens it.
 * Every path component is checked with lstat so a sandbox cannot swap a
 * directory or payload for a symlink between request validation and publish. */
export function assertSafeStagingPayload(stagingRoot: string, stagingPath: string): void {
  const root = resolve(stagingRoot);
  const target = resolve(stagingPath);
  const rel = relative(root, target);
  if (!rel || rel === '..' || rel.startsWith('../') || isAbsolute(rel)) fail('staging payload escapes current session');
  let cursor = root;
  const rootStat = lstatSync(cursor);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail('staging root is not a real directory');
  for (const part of rel.split('/')) {
    cursor = join(cursor, part);
    const stat = lstatSync(cursor);
    if (stat.isSymbolicLink()) fail('staging payload may not use symlinks');
    if (cursor !== target && !stat.isDirectory()) fail('staging payload parent is not a directory');
  }
  const targetStat = lstatSync(target);
  if (targetStat.isSymbolicLink()) fail('staging payload may not use symlinks');
  if (targetStat.isFile()) return;
  if (!targetStat.isDirectory()) fail('staging payload must be a regular file or directory');
  // qlib's publish contract uses one request directory containing `payload/`
  // and `submission.toml`.  Walk the tree without following symlinks so the
  // host can safely hand it to the format-only T3 validator.
  const walk = (directory: string): void => {
    for (const entry of readdirSync(directory)) {
      const child = join(directory, entry);
      const stat = lstatSync(child);
      if (stat.isSymbolicLink()) fail('staging payload may not use symlinks');
      if (stat.isDirectory()) walk(child);
      else if (!stat.isFile()) fail('staging payload contains a special file');
    }
  };
  walk(target);
}

/**
 * Poll a session outbox without following symlinks. A request is consumed only
 * after the callback succeeds; duplicate request IDs are remembered for the
 * lifetime of this watcher and accepted files are removed/renamed.
 */
export class DataPublishRelay {
  private readonly seen = new Set<string>();
  private timer: ReturnType<typeof setInterval> | undefined;
  private polling = false;

  constructor(private readonly input: {
    readonly outboxRoot: string;
    readonly sessionId: string;
    readonly sessionStagingRoot: string;
    /** Hashes come from the host session, never from the outbox writer. */
    readonly expectedSessionHash?: string;
    readonly expectedOwnerOpenIdHash?: string;
    readonly capability: () => DataPublishCapability | undefined;
    readonly onRequest: (request: ValidatedDataPublishRequest) => Promise<void> | void;
    readonly intervalMs?: number;
  }) {}

  async pollOnce(): Promise<number> {
    // The interval callback is deliberately fire-and-forget. Serialize scans
    // so a slow qlib/Postgres submission cannot cause two callbacks to claim
    // the same outbox file before either one records `seen`.
    if (this.polling) return 0;
    this.polling = true;
    try {
      return await this.pollOnceUnlocked();
    } finally {
      this.polling = false;
    }
  }

  private async pollOnceUnlocked(): Promise<number> {
    if (!existsSync(this.input.outboxRoot)) return 0;
    let names: string[];
    try { names = readdirSync(this.input.outboxRoot); } catch { return 0; }
    let accepted = 0;
    for (const name of names.filter(entry => DATA_PUBLISH_REQUEST_RE.test(entry)).sort()) {
      const filenameKey = name.slice(0, -'.json'.length);
      if (this.seen.has(filenameKey)) continue;
      const path = join(this.input.outboxRoot, name);
      let snapshotPath: string | undefined;
      let stagingSnapshotRoot: string | undefined;
      let callbackSucceeded = false;
      try {
        const claim = this.input.capability();
        if (!claim) continue;
        const parsed = readDataPublishRequestFile(path);
        const validated = validateDataPublishRequest({
          raw: parsed.raw,
          outboxRoot: this.input.outboxRoot,
          currentSessionId: this.input.sessionId,
          sessionStagingRoot: this.input.sessionStagingRoot,
          currentCapability: claim,
          expectedSessionHash: this.input.expectedSessionHash,
          expectedOwnerOpenIdHash: this.input.expectedOwnerOpenIdHash,
          requestFileName: name,
        });
        assertSafeStagingPayload(this.input.sessionStagingRoot, validated.stagingPath);
        const snapshotRoot = ensureHostSnapshotDirectory(this.input.outboxRoot);
        snapshotPath = writeRequestSnapshot(snapshotRoot, name, parsed.body);
        const stagingSnapshot = createStagingSnapshot({
          snapshotRoot,
          sourceRoot: this.input.sessionStagingRoot,
          sourcePath: validated.stagingPath,
          requestId: validated.requestId,
          payloadHash: validated.payloadHash,
        });
        stagingSnapshotRoot = stagingSnapshot.root;
        // From this point on, the callback and qlib bridge only receive the
        // host-owned request and staging snapshots. The child-writable source
        // is never opened again.
        await this.input.onRequest({
          ...validated,
          requestPath: snapshotPath,
          snapshotRoot,
          stagingSnapshotRoot: stagingSnapshot.root,
          stagingSnapshotPath: stagingSnapshot.path,
        });
        callbackSucceeded = true;
        // The relay owns the source outbox lifecycle. Exactly one authoritative
        // source transition happens here; qlib consumes only its own copy.
        renameSync(path, `${path}.accepted`);
        this.seen.add(filenameKey);
        accepted += 1;
      } catch {
        // Invalid or stale requests are quarantined, never retried forever.
        try { renameSync(path, `${path}.rejected`); } catch { /* concurrent cleanup */ }
      } finally {
        if (snapshotPath) {
          try { unlinkSync(snapshotPath); } catch { /* callback/bridge may have consumed it */ }
        }
        if (!callbackSucceeded && stagingSnapshotRoot) {
          try { rmSync(stagingSnapshotRoot, { recursive: true, force: true }); } catch { /* best effort */ }
        }
      }
    }
    return accepted;
  }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => { void this.pollOnce(); }, this.input.intervalMs ?? 250);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }
}
