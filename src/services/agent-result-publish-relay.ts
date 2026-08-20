/**
 * Host-side relay for research-result publication requests emitted by a guest.
 *
 * This is deliberately a separate protocol from the older lake/data-publish
 * relay.  A result request is an untrusted, file-only envelope: the guest may
 * name a staging child and provide hashes, but it cannot provide a database
 * URL, an artifact root, a formal result status, or executable code.  The
 * watcher snapshots both the envelope and the staging tree before handing
 * anything to the host consumer.
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  readSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';

export const RESULT_PUBLISH_CAPABILITY_BASENAME = '.botmux-result-publish-capability.json';
export const RESULT_PUBLISH_REQUEST_PREFIX = 'result-publish-';
export const RESULT_PUBLISH_SNAPSHOT_DIRNAME = '.botmux-result-publish-snapshots';
export const RESULT_PUBLISH_REQUEST_KIND = 'research_result_publish_request';
export const RESULT_PUBLISH_REQUEST_VERSION = 1 as const;

/** qrant-qlib names the immutable outbox file with the idempotency digest. */
const RESULT_PUBLISH_REQUEST_RE = /^[a-f0-9]{64}\.json$/u;
const HASH_RE = /^[a-f0-9]{64}$/u;
const MAX_REQUEST_BYTES = 128 * 1024;
const MAX_STAGING_FILE_BYTES = 256 * 1024 * 1024;
const MAX_STAGING_TOTAL_BYTES = 512 * 1024 * 1024;
const O_NOFOLLOW = fsConstants.O_NOFOLLOW ?? 0;
const O_DIRECTORY = fsConstants.O_DIRECTORY ?? 0;
const MANIFEST_KEYS = new Set([
  'version', 'kind', 'session_hash', 'owner_open_id_hash', 'turn_id', 'capability',
  'strategy_id', 'strategy_name', 'run_id', 'campaign_id', 'factor_id', 'model_id',
  'market', 'engine', 'data_snapshot_hash', 'code_hash', 'stage', 'initial_cash',
  'parameters', 'metrics', 'metadata', 'artifacts',
]);
const ARTIFACT_KEYS = new Set(['path', 'kind', 'lifecycle']);
const EXECUTABLE_SUFFIXES = new Set([
  '.py', '.pyc', '.pyo', '.ipynb', '.sh', '.bash', '.zsh', '.fish', '.js', '.ts',
  '.tsx', '.jsx', '.rb', '.pl', '.php', '.lua', '.so', '.dylib', '.dll', '.exe',
  '.bin', '.pickle', '.pkl', '.joblib',
]);
const DATA_SUFFIXES = new Set(['.parquet', '.csv', '.json', '.jsonl', '.ndjson']);

export interface ResultPublishCapability {
  readonly sessionId: string;
  readonly capability: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly turnId: string;
  readonly dispatchAttempt?: number;
}

/** Shape emitted by qrant-qlib's compatibility guest submit helper. */
export interface ResultPublishRequest {
  readonly version: 1;
  readonly kind: typeof RESULT_PUBLISH_REQUEST_KIND;
  readonly request_id: string;
  readonly staging_path: string;
  readonly manifest_path: string;
  readonly session_hash: string;
  readonly owner_open_id_hash: string;
  readonly payload_hash: string;
  readonly manifest_hash: string;
  readonly idempotency_key: string;
  readonly capability: string;
  readonly turn_id: string;
}

export interface ValidatedResultPublishRequest {
  readonly requestId: string;
  readonly idempotencyKey: string;
  /** Child path, retained for audit only. Bridges must use the snapshots. */
  readonly stagingPath: string;
  /** Manifest child path, retained only for snapshot derivation. */
  readonly manifestPath: string;
  /** Host-only immutable envelope snapshot. */
  readonly requestPath: string;
  readonly snapshotRoot: string;
  /** Host-only private staging snapshot handed to the consumer. */
  readonly stagingSnapshotRoot: string;
  readonly stagingSnapshotPath: string;
  /** Host-only immutable manifest snapshot handed to the consumer. */
  readonly manifestSnapshotPath: string;
  readonly capability: string;
  readonly sessionId: string;
  readonly sessionHash: string;
  readonly ownerOpenIdHash: string;
  readonly payloadHash: string;
  readonly manifestHash: string;
  readonly turnId: string;
}

export type ResearchResultPublishCapability = ResultPublishCapability;
export type ResearchResultPublishRequest = ResultPublishRequest;
export type ValidatedResearchResultPublishRequest = ValidatedResultPublishRequest;

function fail(message: string): never {
  throw new Error(`[result-relay] ${message}`);
}

function safeText(value: unknown, name: string, maxLength = 256): string {
  if (typeof value !== 'string' || value.trim() === '' || value.length > maxLength
    || /[\u0000\r\n]/u.test(value)) fail(`invalid ${name}`);
  return value.trim();
}

function safeSessionId(value: unknown): string {
  return safeText(value, 'session id', 256);
}

function safeToken(value: unknown): string {
  const token = safeText(value, 'capability', 128);
  if (!/^[a-f0-9]{32,128}$/iu.test(token)) fail('invalid capability');
  return token;
}

function safeHash(value: unknown, name: string): string {
  const hash = safeText(value, name, 64);
  if (!HASH_RE.test(hash)) fail(`invalid ${name}`);
  return hash;
}

/** qrant's session/principal bindings are opaque identity hashes.  Podman
 * currently uses 24-character SHA-256 prefixes, while the qlib test harness
 * also uses readable opaque identities; both remain host-bound below. */
function safeEnvelopeIdentity(value: unknown, name: string): string {
  const identity = safeText(value, name, 256);
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$/u.test(identity)) fail(`invalid ${name}`);
  return identity;
}

/**
 * qrant's compatibility result protocol uses full SHA-256 identity strings,
 * while Podman runtime paths intentionally use only a 24-character prefix.
 * Derive a separate, stable result-protocol identity from that opaque runtime
 * value so the guest never receives a short path identifier where qlib expects
 * a digest.  The input is already non-sensitive and contains no owner text.
 */
export function deriveResultPublishIdentityHash(value: string): string {
  const identity = safeEnvelopeIdentity(value, 'runtime identity');
  return createHash('sha256').update(`botmux-result-publish-v1:${identity}`, 'utf8').digest('hex');
}

function safeRequestId(value: unknown): string {
  const id = safeText(value, 'request id', 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(id)) fail('invalid request id');
  return id;
}

function safeSource(value: unknown): readonly string[] {
  if (!Array.isArray(value) || value.length > 32) fail('invalid source');
  return value.map(item => safeText(item, 'source item', 256));
}

/** Relative POSIX paths only.  The host derives the absolute path from its
 * current session root; a child cannot smuggle an absolute host path. */
export function safeResultRelativePath(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.trim() === '' || value.includes('\0')
    || value.includes('\\') || isAbsolute(value)) {
    fail(`${name} must be a relative POSIX path`);
  }
  const normalized = value.trim();
  const parts = normalized.split('/');
  if (parts.some(part => part === '' || part === '.' || part === '..')) {
    fail(`${name} contains traversal`);
  }
  return normalized;
}

function equalSecret(left: string, right: string): boolean {
  const a = Buffer.from(left, 'utf8');
  const b = Buffer.from(right, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(item => canonicalJson(item)).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function isWithin(parent: string, candidate: string): boolean {
  const rel = relative(parent, candidate);
  return rel === '' || (!isAbsolute(rel) && rel !== '..' && !rel.startsWith('../'));
}

function ensurePrivateDirectory(path: string): void {
  try {
    const stat = lstatSync(path);
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail('relay directory is not a real directory');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    mkdirSync(path, { recursive: true, mode: 0o700 });
  }
  chmodSync(path, 0o700);
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail('relay directory is not a real directory');
}

function atomicWrite(path: string, body: string): void {
  const temporary = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
  writeFileSync(temporary, body, { encoding: 'utf8', mode: 0o600 });
  chmodSync(temporary, 0o600);
  renameSync(temporary, path);
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

export function resultPublishSnapshotRoot(outboxRoot: string): string {
  const outbox = resolve(outboxRoot);
  const snapshot = resolve(dirname(outbox), RESULT_PUBLISH_SNAPSHOT_DIRNAME);
  if (snapshot === outbox || isWithin(outbox, snapshot) || isWithin(snapshot, outbox)) {
    fail('result publish snapshot directory must be a sibling of the outbox');
  }
  return snapshot;
}

function ensureSnapshotDirectory(outboxRoot: string): string {
  const outbox = resolve(outboxRoot);
  const outboxStat = lstatSync(outbox);
  if (!outboxStat.isDirectory() || outboxStat.isSymbolicLink()) fail('outbox must be a real directory');
  const parentStat = lstatSync(dirname(outbox));
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()) fail('outbox parent must be a real directory');
  const snapshot = resultPublishSnapshotRoot(outbox);
  try {
    const stat = lstatSync(snapshot);
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail('result snapshot root is not a real directory');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    mkdirSync(snapshot, { mode: 0o700 });
  }
  chmodSync(snapshot, 0o700);
  const stat = lstatSync(snapshot);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail('result snapshot root is not a real directory');
  if (isLinuxMountPoint(snapshot)) fail('result snapshot root may not be a mount point');
  return snapshot;
}

function readRequestFile(path: string): { readonly raw: unknown; readonly body: string } {
  let fd: number | undefined;
  try {
    fd = openSync(path, fsConstants.O_RDONLY | O_NOFOLLOW);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_REQUEST_BYTES
      || (stat.mode & 0o077) !== 0) {
      fail('request file must be a small regular file');
    }
    const body = readFileSync(fd, 'utf8');
    return { raw: JSON.parse(body) as unknown, body };
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function readManifestText(path: string): string {
  let fd: number | undefined;
  try {
    fd = openSync(path, fsConstants.O_RDONLY | O_NOFOLLOW);
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size <= 0 || stat.size > MAX_REQUEST_BYTES) {
      fail('manifest must be a small regular file');
    }
    const body = readFileSync(fd, 'utf8');
    if (/\u0000/u.test(body)) fail('manifest contains invalid data');
    return body;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function tomlIdentifier(body: string, name: string): string {
  const match = body.match(new RegExp(`(?:^|\\n)\\s*${name}\\s*=\\s*["']([^"']+)["']`, 'u'));
  if (!match?.[1]) fail(`manifest ${name} is missing`);
  return safeRequestId(match[1]);
}

function tomlEnvelope(body: string, name: string): string {
  const match = body.match(new RegExp(`(?:^|\\n)\\s*${name}\\s*=\\s*["']([^"']+)["']`, 'u'));
  if (!match?.[1]) fail(`manifest ${name} is missing`);
  return name === 'capability' ? safeToken(match[1]) : safeEnvelopeIdentity(match[1], name);
}

function assertManifestNotHostControl(body: string): void {
  if (/^\s*(?:formal_status|dsn|database_url|artifact_root|python|python_code|command|entrypoint)\s*=/imu.test(body)
    || /(^|\n)\s*stage\s*=\s*["']formal["']/u.test(body)) {
    fail('manifest contains forbidden host-control fields');
  }
}

function validateCompatManifestSource(input: {
  readonly manifestPath: string;
  readonly sessionHash: string;
  readonly ownerOpenIdHash: string;
  readonly turnId: string;
  readonly capability: string;
  readonly payloadHash: string;
  readonly idempotencyKey: string;
}): void {
  const body = readManifestText(input.manifestPath);
  assertManifestNotHostControl(body);
  const optionalBindings: Array<[string, string, string]> = [
    ['session_hash', input.sessionHash, 'session hash'],
    ['owner_open_id_hash', input.ownerOpenIdHash, 'owner hash'],
    ['turn_id', input.turnId, 'turn id'],
    ['capability', input.capability, 'capability'],
  ];
  for (const [name, expected, label] of optionalBindings) {
    const match = body.match(new RegExp(`(?:^|\\n)\\s*${name}\\s*=\\s*["']([^"']+)["']`, 'u'));
    if (match?.[1] !== undefined && !equalSecret(match[1], expected)) fail(`manifest ${label} does not match host binding`);
  }
  const strategyId = tomlIdentifier(body, 'strategy_id');
  const runId = tomlIdentifier(body, 'run_id');
  const expectedIdempotency = createHash('sha256')
    .update(`${input.sessionHash}${strategyId}${runId}${input.payloadHash}`, 'utf8')
    .digest('hex');
  if (!equalSecret(expectedIdempotency, input.idempotencyKey)) fail('idempotency key is invalid');
}

function writeRequestSnapshot(snapshotRoot: string, sourceName: string, body: string): string {
  const path = join(snapshotRoot, `${sourceName}.${process.pid}.${randomBytes(16).toString('hex')}.json`);
  atomicWrite(path, body);
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > MAX_REQUEST_BYTES) {
    try { unlinkSync(path); } catch { /* best effort */ }
    fail('request snapshot is not a regular file');
  }
  chmodSync(path, 0o600);
  return path;
}

function readDirectoryEntries(fd: number, fallback: string): string[] {
  return process.platform === 'linux' ? readdirSync(`/proc/self/fd/${fd}`) : readdirSync(fallback);
}

function sourceChildPath(fd: number, parent: string, name: string): string {
  return process.platform === 'linux' ? `/proc/self/fd/${fd}/${name}` : join(parent, name);
}

interface CopyState { totalBytes: number }

function copyRegularFile(source: string, destination: string, state: CopyState): void {
  let sourceFd: number | undefined;
  let destinationFd: number | undefined;
  const temporary = `${destination}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
  try {
    sourceFd = openSync(source, fsConstants.O_RDONLY | O_NOFOLLOW);
    const sourceStat = fstatSync(sourceFd);
    if (!sourceStat.isFile() || sourceStat.isSymbolicLink() || sourceStat.size > MAX_STAGING_FILE_BYTES) {
      fail('staging contains a non-regular or oversized file');
    }
    state.totalBytes += sourceStat.size;
    if (state.totalBytes > MAX_STAGING_TOTAL_BYTES) fail('staging tree is oversized');
    mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
    destinationFd = openSync(temporary, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | O_NOFOLLOW, 0o600);
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    while (true) {
      const count = readSync(sourceFd, buffer, 0, buffer.length, null);
      if (count === 0) break;
      let offset = 0;
      while (offset < count) offset += writeSync(destinationFd, buffer, offset, count - offset, null);
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

function copyEntry(source: string, destination: string, state: CopyState): void {
  let sourceFd: number | undefined;
  try {
    const sourceStat = lstatSync(source);
    if (sourceStat.isSymbolicLink()) fail('staging may not use symlinks');
    if (sourceStat.isDirectory()) {
      sourceFd = openSync(source, fsConstants.O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
      mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
      mkdirSync(destination, { recursive: false, mode: 0o700 });
      chmodSync(destination, 0o700);
      for (const name of readDirectoryEntries(sourceFd, source)) {
        copyEntry(sourceChildPath(sourceFd, source, name), join(destination, name), state);
      }
      return;
    }
    if (!sourceStat.isFile()) fail('staging contains a special file');
    copyRegularFile(source, destination, state);
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
      fail('snapshot contains a non-regular or oversized file');
    }
    const digest = createHash('sha256');
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    while (true) {
      const count = readSync(fd, buffer, 0, buffer.length, null);
      if (count === 0) break;
      digest.update(buffer.subarray(0, count));
    }
    return digest.digest('hex');
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function assertNonExecutablePayload(path: string): void {
  let fd: number | undefined;
  try {
    fd = openSync(path, fsConstants.O_RDONLY | O_NOFOLLOW);
    const prefix = Buffer.alloc(4);
    const count = readSync(fd, prefix, 0, prefix.length, null);
    if ((count >= 2 && prefix[0] === 0x23 && prefix[1] === 0x21)
      || (count >= 4 && prefix[0] === 0x7f && prefix[1] === 0x45 && prefix[2] === 0x4c && prefix[3] === 0x46)) {
      fail('snapshot payload contains executable data');
    }
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function walkRegularFiles(root: string): string[] {
  const result: string[] = [];
  const walk = (directory: string): void => {
    for (const name of readdirSync(directory).sort()) {
      const path = join(directory, name);
      const stat = lstatSync(path);
      if (stat.isSymbolicLink()) fail('snapshot may not use symlinks');
      if (stat.isDirectory()) {
        if (isLinuxMountPoint(path)) fail('snapshot payload may not contain a mount point');
        walk(path);
      }
      else if (stat.isFile()) {
        if ((stat.mode & 0o111) !== 0) fail('snapshot payload files may not be executable');
        const suffix = path.slice(path.lastIndexOf('.')).toLowerCase();
        if (EXECUTABLE_SUFFIXES.has(suffix) || !DATA_SUFFIXES.has(suffix)) {
          fail('snapshot payload format is not publishable');
        }
        if (lstatSync(path).size <= 0) fail('snapshot payload files must be non-empty');
        assertNonExecutablePayload(path);
        result.push(path);
      }
      else fail('snapshot contains a special file');
    }
  };
  walk(root);
  return result;
}

/**
 * Hash the payload tree used by result-publish.  qrant-qlib normally writes
 * `payload/`; accepting a flat staging directory keeps this boundary useful
 * for older result producers while still hashing every regular file except
 * the separately authenticated manifest.
 */
export function computeResultPayloadHash(stagingRoot: string, manifestPath?: string): string {
  const root = resolve(stagingRoot);
  const payloadRoot = (() => {
    const candidate = join(root, 'payload');
    try {
      const stat = lstatSync(candidate);
      return stat.isDirectory() && !stat.isSymbolicLink() ? candidate : root;
    } catch { return root; }
  })();
  const manifest = manifestPath === undefined ? undefined : resolve(manifestPath);
  const files = walkRegularFiles(payloadRoot).filter(path => manifest === undefined || resolve(path) !== manifest);
  if (files.length === 0) fail('result payload is empty');
  const entries = files.map(path => {
    const stat = lstatSync(path);
    return [relative(root, path).split('\\').join('/'), stat.size, hashRegularFile(path)];
  });
  return createHash('sha256').update(JSON.stringify(entries)).digest('hex');
}

function assertContainedRegularTree(rootRaw: string, targetRaw: string, label: string): void {
  const root = resolve(rootRaw);
  const target = resolve(targetRaw);
  const rel = relative(root, target);
  if (!rel || rel === '..' || rel.startsWith('../') || isAbsolute(rel)) fail(`${label} escapes session`);
  const rootStat = lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) fail(`${label} root is not a real directory`);
  let cursor = root;
  for (const part of rel.split('/')) {
    cursor = join(cursor, part);
    const stat = lstatSync(cursor);
    if (stat.isSymbolicLink()) fail(`${label} may not use symlinks`);
    if (cursor !== target && !stat.isDirectory()) fail(`${label} parent is not a directory`);
  }
  const targetStat = lstatSync(target);
  if (targetStat.isSymbolicLink()) fail(`${label} may not use symlinks`);
  if (!targetStat.isDirectory() && !targetStat.isFile()) fail(`${label} must be a file or directory`);
}

function createStagingSnapshot(input: {
  readonly snapshotRoot: string;
  readonly sourceRoot: string;
  readonly sourcePath: string;
  readonly requestId: string;
}): { readonly root: string; readonly path: string } {
  const sourceRoot = resolve(input.sourceRoot);
  const sourcePath = resolve(input.sourcePath);
  const rel = relative(sourceRoot, sourcePath);
  if (!rel || rel === '..' || rel.startsWith('../') || isAbsolute(rel)) fail('staging snapshot escapes session');
  const jobsRoot = join(input.snapshotRoot, 'staging-jobs');
  ensurePrivateDirectory(jobsRoot);
  const root = join(jobsRoot, `${input.requestId}.${randomBytes(12).toString('hex')}`);
  mkdirSync(root, { recursive: false, mode: 0o700 });
  try {
    copyEntry(sourcePath, join(root, rel), { totalBytes: 0 });
    atomicWrite(join(root, '.botmux-private-staging'), 'botmux-private-staging-v1\n');
    return { root, path: join(root, rel) };
  } catch (error) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
    throw error;
  }
}

function validateCanonicalManifest(raw: unknown, expectedSessionHash: string): {
  readonly manifest: Readonly<Record<string, unknown>>;
  readonly sessionHash: string;
  readonly ownerOpenIdHash: string;
  readonly turnId: string;
  readonly capability: string;
  readonly strategyId: string;
  readonly runId: string;
  readonly manifestHash: string;
} {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail('manifest must be an object');
  const manifest = raw as Record<string, unknown>;
  const unknown = Object.keys(manifest).filter(key => !MANIFEST_KEYS.has(key));
  if (unknown.length > 0) fail('manifest contains forbidden fields');
  if ([...MANIFEST_KEYS].some(key => !Object.prototype.hasOwnProperty.call(manifest, key))) {
    fail('manifest is not canonical');
  }
  if (manifest.version !== 1 || manifest.kind !== RESULT_PUBLISH_REQUEST_KIND) fail('manifest version or kind is invalid');
  const sessionHash = safeEnvelopeIdentity(manifest.session_hash, 'session hash');
  const ownerOpenIdHash = safeEnvelopeIdentity(manifest.owner_open_id_hash, 'owner hash');
  const turnId = safeText(manifest.turn_id, 'turn id');
  const capability = safeToken(manifest.capability);
  const strategyId = safeRequestId(manifest.strategy_id);
  const runId = safeRequestId(manifest.run_id);
  if (sessionHash !== safeEnvelopeIdentity(expectedSessionHash, 'host session hash')) fail('session hash does not match current session');
  safeText(manifest.strategy_name, 'strategy name', 512);
  safeRequestId(manifest.campaign_id);
  const market = safeText(manifest.market, 'market', 64);
  if (!['a_share', 'us', 'crypto'].includes(market)) fail('manifest market is invalid');
  const engine = safeText(manifest.engine, 'engine', 64);
  if (!['qlib', 'nautilus', 'vectorbt', 'research'].includes(engine)) fail('manifest engine is invalid');
  safeText(manifest.data_snapshot_hash, 'data snapshot hash', 512);
  safeText(manifest.code_hash, 'code hash', 512);
  if (manifest.stage === 'formal' || manifest.formal_status !== undefined) fail('guest result cannot declare formal status');
  if (typeof manifest.stage !== 'string' || !['experimental', 'research', 'research_only', 'candidate', 'final_candidate'].includes(manifest.stage)) {
    fail('manifest stage is invalid');
  }
  for (const name of ['parameters', 'metrics', 'metadata']) {
    const value = manifest[name];
    if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`manifest ${name} is invalid`);
  }
  if (manifest.initial_cash !== null && manifest.initial_cash !== undefined
    && (typeof manifest.initial_cash === 'object' || typeof manifest.initial_cash === 'function')) {
    fail('manifest initial_cash is invalid');
  }
  if (!manifest.artifacts || !Array.isArray(manifest.artifacts) || manifest.artifacts.length === 0) fail('manifest artifacts are invalid');
  for (const artifact of manifest.artifacts) {
    if (!artifact || typeof artifact !== 'object' || Array.isArray(artifact)) fail('manifest artifact is invalid');
    const row = artifact as Record<string, unknown>;
    if (Object.keys(row).some(key => !ARTIFACT_KEYS.has(key))) fail('manifest artifact contains forbidden fields');
    const path = safeResultRelativePath(row.path, 'artifact path');
    if (!path.startsWith('payload/')) fail('artifact path must stay below payload');
    if (EXECUTABLE_SUFFIXES.has(path.slice(path.lastIndexOf('.')).toLowerCase())) fail('manifest declares executable artifact');
    safeRequestId(row.kind);
    const lifecycle = safeText(row.lifecycle, 'artifact lifecycle', 64);
    if (!['failed_14d', 'intermediate_30d', 'validation_keep', 'promoted_keep'].includes(lifecycle)) {
      fail('manifest artifact lifecycle is invalid');
    }
  }
  const hash = createHash('sha256').update(canonicalJson(manifest), 'utf8').digest('hex');
  return { manifest, sessionHash, ownerOpenIdHash, turnId, capability, strategyId, runId, manifestHash: hash };
}

export function createResultPublishCapability(
  sessionId: string,
  turnId: string,
  ttlMs = 5 * 60_000,
  now = Date.now(),
  dispatchAttempt?: number,
): ResultPublishCapability {
  const sid = safeSessionId(sessionId);
  const turn = safeText(turnId, 'turn id');
  if (dispatchAttempt !== undefined && (!Number.isSafeInteger(dispatchAttempt) || dispatchAttempt < 0)) {
    fail('invalid dispatch attempt');
  }
  return {
    sessionId: sid,
    turnId: turn,
    capability: randomBytes(32).toString('hex'),
    issuedAt: now,
    expiresAt: now + Math.max(1_000, Math.min(ttlMs, 15 * 60_000)),
    ...(dispatchAttempt !== undefined ? { dispatchAttempt } : {}),
  };
}

export function publishResultPublishCapability(outboxRoot: string, claim: ResultPublishCapability): string {
  ensurePrivateDirectory(outboxRoot);
  const path = join(outboxRoot, RESULT_PUBLISH_CAPABILITY_BASENAME);
  atomicWrite(path, JSON.stringify(claim) + '\n');
  return path;
}

export function readResultPublishCapability(
  outboxRoot: string,
  now = Date.now(),
): ResultPublishCapability | undefined {
  const path = join(outboxRoot, RESULT_PUBLISH_CAPABILITY_BASENAME);
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 4096) return undefined;
    const raw = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
    const claim: ResultPublishCapability = {
      sessionId: safeSessionId(raw.sessionId),
      capability: safeToken(raw.capability),
      issuedAt: Number(raw.issuedAt),
      expiresAt: Number(raw.expiresAt),
      turnId: safeText(raw.turnId, 'turn id'),
      ...(raw.dispatchAttempt !== undefined ? { dispatchAttempt: Number(raw.dispatchAttempt) } : {}),
    };
    if (!Number.isFinite(claim.issuedAt) || !Number.isFinite(claim.expiresAt) || claim.expiresAt <= now) return undefined;
    if (claim.dispatchAttempt !== undefined
      && (!Number.isSafeInteger(claim.dispatchAttempt) || claim.dispatchAttempt < 0)) return undefined;
    return claim;
  } catch { return undefined; }
}

/** Validate the guest envelope and derive all host paths from current session state. */
export function validateResultPublishRequest(input: {
  readonly raw: unknown;
  readonly outboxRoot: string;
  readonly currentSessionId: string;
  readonly sessionStagingRoot: string;
  readonly currentCapability: ResultPublishCapability;
  readonly expectedSessionHash: string;
  readonly expectedOwnerOpenIdHash: string;
  readonly requestFileName?: string;
  readonly now?: number;
}): Omit<ValidatedResultPublishRequest, 'requestPath' | 'stagingSnapshotRoot' | 'stagingSnapshotPath' | 'manifestSnapshotPath'> {
  if (!input.raw || typeof input.raw !== 'object' || Array.isArray(input.raw)) fail('request must be an object');
  const raw = input.raw as Record<string, unknown>;
  const allowed = new Set([
    'version', 'kind', 'request_id', 'staging_path', 'manifest_path', 'session_hash',
    'owner_open_id_hash', 'payload_hash', 'manifest_hash', 'idempotency_key', 'capability', 'turn_id',
  ]);
  const unknown = Object.keys(raw).filter(key => !allowed.has(key));
  if (unknown.length > 0) fail('request contains forbidden fields');
  if ([...allowed].some(key => !Object.prototype.hasOwnProperty.call(raw, key))) {
    fail('request is not canonical');
  }
  if (raw.version !== RESULT_PUBLISH_REQUEST_VERSION || raw.kind !== RESULT_PUBLISH_REQUEST_KIND) {
    fail('unsupported research result publish request version');
  }
  const requestId = safeRequestId(raw.request_id);
  const idempotencyKey = safeHash(raw.idempotency_key, 'idempotency key');
  if (requestId !== idempotencyKey) fail('request id does not match idempotency key');
  const stagingRelativePath = safeResultRelativePath(raw.staging_path, 'staging_path');
  const manifestRelativePath = safeResultRelativePath(raw.manifest_path, 'manifest_path');
  const sessionHash = safeEnvelopeIdentity(raw.session_hash, 'session hash');
  const ownerOpenIdHash = safeEnvelopeIdentity(raw.owner_open_id_hash, 'owner hash');
  const payloadHash = safeHash(raw.payload_hash, 'payload hash');
  const manifestHash = safeHash(raw.manifest_hash, 'manifest hash');
  const capability = safeToken(raw.capability);
  const turnId = safeText(raw.turn_id, 'turn id');
  const sessionId = safeSessionId(input.currentSessionId);
  const claim = input.currentCapability;
  if (claim.sessionId !== sessionId || claim.expiresAt <= (input.now ?? Date.now())) fail('session capability is stale');
  if (!equalSecret(capability, claim.capability)) fail('capability is stale or forged');
  if (claim.turnId !== turnId) fail('turn capability is stale or forged');
  if (sessionHash !== safeEnvelopeIdentity(input.expectedSessionHash, 'host session hash')) fail('session hash does not match current session');
  if (ownerOpenIdHash !== safeEnvelopeIdentity(input.expectedOwnerOpenIdHash, 'host owner hash')) fail('owner hash does not match current session');
  if (input.requestFileName) {
    if (!RESULT_PUBLISH_REQUEST_RE.test(input.requestFileName)) fail('invalid request filename');
    const filenameKey = input.requestFileName.slice(0, -'.json'.length);
    if (filenameKey !== idempotencyKey) fail('idempotency key does not match its filename');
  }
  const stagingRoot = resolve(input.sessionStagingRoot);
  const stagingPath = resolve(stagingRoot, stagingRelativePath);
  const stagingRel = relative(stagingRoot, stagingPath);
  if (!stagingRel || stagingRel === '..' || stagingRel.startsWith('../') || isAbsolute(stagingRel)) fail('staging path escapes current session');
  const manifestPath = resolve(stagingPath, manifestRelativePath);
  const manifestRel = relative(stagingPath, manifestPath);
  if (!manifestRel || manifestRel === '..' || manifestRel.startsWith('../') || isAbsolute(manifestRel)) fail('manifest path escapes staging request');
  const outbox = resolve(input.outboxRoot);
  const snapshotRoot = resultPublishSnapshotRoot(outbox);
  const requestPath = resolve(outbox, input.requestFileName ?? `${idempotencyKey}.json`);
  if (!isWithin(outbox, requestPath) || requestPath === outbox) fail('request path escapes outbox');
  return {
    requestId,
    idempotencyKey,
    stagingPath,
    capability,
    sessionId,
    sessionHash,
    ownerOpenIdHash,
    payloadHash,
    manifestHash,
    turnId,
    manifestPath,
    snapshotRoot,
  };
}

/** Verify every path component before the snapshot copy starts. */
export function assertSafeResultStaging(stagingRoot: string, stagingPath: string, manifestPath?: string): void {
  assertContainedRegularTree(stagingRoot, stagingPath, 'staging payload');
  const stagingStat = lstatSync(stagingPath);
  if (!stagingStat.isDirectory()) fail('staging payload must be a directory');
  if (isLinuxMountPoint(stagingPath)) fail('staging payload may not be a mount point');
  const payloadPath = join(stagingPath, 'payload');
  const payloadStat = lstatSync(payloadPath);
  if (!payloadStat.isDirectory() || payloadStat.isSymbolicLink()) fail('staging payload directory is invalid');
  if (isLinuxMountPoint(payloadPath)) fail('staging payload may not be a mount point');
  // Walk before copying so symlink/special-file races fail at the host boundary.
  walkRegularFiles(payloadPath);
  if (manifestPath !== undefined) {
    // Compatibility guard for callers shared with the old path-based relay;
    // result-publish itself never accepts a guest manifest path.
    assertContainedRegularTree(stagingPath, manifestPath, 'manifest');
    const manifestStat = lstatSync(manifestPath);
    if (!manifestStat.isFile() || manifestStat.isSymbolicLink()) fail('manifest must be a regular file');
  }
}

function assertManifestArtifacts(stagingPath: string, manifest: Readonly<Record<string, unknown>>): void {
  const actual = new Set(
    walkRegularFiles(join(stagingPath, 'payload'))
      .map(path => relative(stagingPath, path).split('\\').join('/')),
  );
  const declared = new Set<string>();
  const artifacts = Array.isArray(manifest.artifacts) ? manifest.artifacts : [];
  for (const artifact of artifacts) {
    const path = artifact && typeof artifact === 'object' && !Array.isArray(artifact)
      ? (artifact as Record<string, unknown>).path
      : undefined;
    if (typeof path !== 'string' || declared.has(path)) fail('manifest artifact coverage is invalid');
    declared.add(path);
  }
  if (declared.size !== actual.size || [...declared].some(path => !actual.has(path))) {
    fail('manifest artifact coverage does not match payload');
  }
}

export class ResultPublishRelay {
  private readonly fingerprints = new Map<string, string>();
  /** A capability is intentionally one-shot for the result protocol. */
  private readonly consumedCapabilities = new Set<string>();
  private readonly retryAt = new Map<string, number>();
  private timer: ReturnType<typeof setInterval> | undefined;
  private polling = false;

  constructor(private readonly input: {
    readonly outboxRoot: string;
    readonly sessionId: string;
    readonly sessionStagingRoot: string;
    readonly expectedSessionHash: string;
    readonly expectedOwnerOpenIdHash: string;
    readonly capability: () => ResultPublishCapability | undefined;
    readonly onRequest: (request: ValidatedResultPublishRequest) => Promise<void> | void;
    readonly intervalMs?: number;
  }) {}

  async pollOnce(): Promise<number> {
    if (this.polling) return 0;
    this.polling = true;
    try { return await this.pollOnceUnlocked(); } finally { this.polling = false; }
  }

  private async pollOnceUnlocked(): Promise<number> {
    if (!existsSync(this.input.outboxRoot)) return 0;
    let names: string[];
    try { names = readdirSync(this.input.outboxRoot); } catch { return 0; }
    let accepted = 0;
    for (const name of names.filter(value => RESULT_PUBLISH_REQUEST_RE.test(value)).sort()) {
      const filenameKey = name.slice(0, -'.json'.length);
      const retryKey = `${this.input.outboxRoot}/${name}`;
      if ((this.retryAt.get(retryKey) ?? 0) > Date.now()) continue;
      const path = join(this.input.outboxRoot, name);
      let snapshotPath: string | undefined;
      let stagingSnapshotRoot: string | undefined;
      let callbackSucceeded = false;
      let requestFingerprint: string | undefined;
      let envelopeValidated = false;
      try {
        const claim = this.input.capability();
        if (!claim) continue;
        const parsed = readRequestFile(path);
        const validated = validateResultPublishRequest({
          raw: parsed.raw,
          outboxRoot: this.input.outboxRoot,
          currentSessionId: this.input.sessionId,
          sessionStagingRoot: this.input.sessionStagingRoot,
          currentCapability: claim,
          expectedSessionHash: this.input.expectedSessionHash,
          expectedOwnerOpenIdHash: this.input.expectedOwnerOpenIdHash,
          requestFileName: name,
        });
        envelopeValidated = true;
        if (this.consumedCapabilities.has(validated.capability)) fail('capability has already been consumed');
        // Validate the current guest tree even for a duplicate idempotency
        // request.  A duplicate never reaches the consumer, but malformed
        // symlink/mount trees must not be silently accepted by the watcher.
        assertSafeResultStaging(this.input.sessionStagingRoot, validated.stagingPath, validated.manifestPath);
        validateCompatManifestSource({
          manifestPath: validated.manifestPath,
          sessionHash: validated.sessionHash,
          ownerOpenIdHash: validated.ownerOpenIdHash,
          turnId: validated.turnId,
          capability: validated.capability,
          payloadHash: validated.payloadHash,
          idempotencyKey: validated.idempotencyKey,
        });
        requestFingerprint = `${validated.sessionHash}:${validated.payloadHash}:${validated.manifestHash}`;
        const prior = this.fingerprints.get(validated.idempotencyKey);
        if (prior !== undefined && prior !== requestFingerprint) fail('idempotency key was reused for different payload');
        if (prior !== undefined) {
          // A duplicate that reached this watcher after a successful callback is
          // consumed without registering the host job a second time.
          try { renameSync(path, `${path}.accepted`); } catch { /* concurrent cleanup */ }
          continue;
        }
        const snapshotRoot = ensureSnapshotDirectory(this.input.outboxRoot);
        snapshotPath = writeRequestSnapshot(snapshotRoot, name, parsed.body);
        const stagingSnapshot = createStagingSnapshot({
          snapshotRoot,
          sourceRoot: this.input.sessionStagingRoot,
          sourcePath: validated.stagingPath,
          requestId: validated.requestId,
        });
        stagingSnapshotRoot = stagingSnapshot.root;
        const manifestRelative = relative(validated.stagingPath, validated.manifestPath);
        const manifestSnapshotPath = resolve(stagingSnapshot.path, manifestRelative);
        if (hashRegularFile(manifestSnapshotPath) !== validated.manifestHash) fail('manifest hash changed during snapshot');
        if (computeResultPayloadHash(stagingSnapshot.path, manifestSnapshotPath) !== validated.payloadHash) fail('payload hash changed during snapshot');
        await this.input.onRequest({
          ...validated,
          requestPath: snapshotPath,
          snapshotRoot,
          stagingSnapshotRoot: stagingSnapshot.root,
          stagingSnapshotPath: stagingSnapshot.path,
          manifestSnapshotPath,
        });
        callbackSucceeded = true;
        this.fingerprints.set(validated.idempotencyKey, requestFingerprint);
        this.consumedCapabilities.add(validated.capability);
        renameSync(path, `${path}.accepted`);
        this.retryAt.delete(retryKey);
        accepted += 1;
      } catch (error) {
        // Validation failures are permanent and quarantined.  Consumer/bridge
        // failures leave the original request in place for a later retry; the
        // consumer must perform its own idempotent registration.
        const message = error instanceof Error ? error.message : String(error);
        const permanent = !envelopeValidated
          || message.startsWith('[result-relay]')
          || message.includes('hash changed')
          || message.includes('idempotency key was reused');
        if (permanent) {
          try { renameSync(path, `${path}.rejected`); } catch { /* concurrent cleanup */ }
          this.retryAt.delete(retryKey);
        } else {
          this.retryAt.set(retryKey, Date.now() + 500);
        }
      } finally {
        if (snapshotPath) {
          try { unlinkSync(snapshotPath); } catch { /* callback may have consumed it */ }
        }
        if (stagingSnapshotRoot) {
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

// Descriptive aliases keep the host API readable at call sites and let the
// qrant-qlib naming (`research result publish`) coexist with the short CLI
// spelling (`result-publish`).
export {
  ResultPublishRelay as ResearchResultPublishRelay,
  createResultPublishCapability as createResearchResultPublishCapability,
  publishResultPublishCapability as publishResearchResultPublishCapability,
  publishResultPublishCapability as publishResearchResultCapability,
  readResultPublishCapability as readResearchResultPublishCapability,
  validateResultPublishRequest as validateResearchResultPublishRequest,
};
