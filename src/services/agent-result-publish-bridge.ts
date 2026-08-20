/** Host adapter for the research-result publication consumer in qrant-qlib. */
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  readFileSync,
  unlinkSync,
} from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';

import {
  computeResultPayloadHash,
  type ValidatedResultPublishRequest,
} from './agent-result-publish-relay.js';

/** Fixed compatibility consumer used by the host bridge; it is never guest-configurable. */
export const RESULT_PUBLISH_CONSUMER_MODULE = 'src.data_platform.result_publish_core';
export const RESULT_PUBLISH_CONSUMER_SCRIPT = [
  'import json,sys',
  'from src.data_platform.result_publish_core import consume',
  'body=json.load(sys.stdin)',
  'print(json.dumps(consume(body),separators=(",",":")))',
].join(';');
const MAX_STDOUT_BYTES = 64 * 1024;
const MAX_STDERR_BYTES = 8 * 1024;
const DEFAULT_TIMEOUT_MS = 120_000;

export interface ResultPublishBridgeResult {
  readonly resultId?: string;
  readonly idempotencyKey?: string;
  readonly status?: string;
  readonly accepted: boolean;
}

export interface ResultPublishBridgeOptions {
  readonly qlibRoot: string;
  /** Host-only database URL. Never read from the guest request. */
  readonly dsn?: string;
  /** Fixed host-owned artifact root; never accepted from the guest request. */
  readonly trustedArtifactRoot?: string;
  /** Defaults to uv; tests may inject a fake executable. */
  readonly command?: string;
  readonly timeoutMs?: number;
  /** Optional digest pin for deployments that publish a qlib source digest. */
  readonly qlibDigest?: string;
  readonly run?: (input: {
    readonly command: string;
    readonly args: readonly string[];
    readonly cwd: string;
    readonly env: NodeJS.ProcessEnv;
    readonly stdin: string;
    readonly timeoutMs: number;
  }) => Promise<{ readonly status: number | null; readonly stdout: string; readonly stderr: string }>;
}

function safeRoot(value: string): string {
  const lexical = resolve(value);
  if (!isAbsolute(lexical) || !existsSync(lexical)) throw new Error('result publish qlib host adapter is unavailable');
  const stat = lstatSync(lexical);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('result publish qlib root is not a real directory');
  const pyproject = join(lexical, 'pyproject.toml');
  const pyprojectStat = lstatSync(pyproject);
  if (!pyprojectStat.isFile() || pyprojectStat.isSymbolicLink()) throw new Error('result publish qlib root is invalid');
  return lexical;
}

function safeDigest(value: string | undefined): string | undefined {
  if (value === undefined || value.trim() === '') return undefined;
  if (!/^[a-f0-9]{64}$/u.test(value)) throw new Error('result publish qlib digest is invalid');
  return value;
}

function digestQlibRoot(root: string): string {
  // The deployment pin covers the fixed project descriptor and source entry
  // point.  It is deliberately cheap enough to verify before every request;
  // the container image itself remains digest-pinned by the execution config.
  const digest = createHash('sha256');
  for (const path of [
    join(root, 'pyproject.toml'),
    join(root, 'src', 'data_platform', 'result_publish_core.py'),
    join(root, 'src', 'result_publish', 'guest.py'),
    join(root, 'src', 'result_publish', 'consumer.py'),
    join(root, 'src', 'result_publish', 'cli.py'),
  ]) {
    let stat;
    try { stat = lstatSync(path); } catch { throw safeBridgeError('fixed qlib consumer source is unavailable'); }
    if (!stat.isFile() || stat.isSymbolicLink()) throw safeBridgeError('fixed qlib consumer source is invalid');
    digest.update(readFileSync(path));
  }
  return digest.digest('hex');
}

function bounded(value: string, max: number): string {
  return value.length <= max ? value : value.slice(0, max);
}

function defaultRun(input: {
  readonly command: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env: NodeJS.ProcessEnv;
  readonly stdin: string;
  readonly timeoutMs: number;
}): Promise<{ readonly status: number | null; readonly stdout: string; readonly stderr: string }> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(input.command, [...input.args], {
      cwd: input.cwd,
      env: input.env,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, input.timeoutMs);
    timer.unref?.();
    child.stdout.on('data', chunk => {
      if (stdout.length < MAX_STDOUT_BYTES) stdout += String(chunk);
    });
    child.stderr.on('data', chunk => {
      if (stderr.length < MAX_STDERR_BYTES) stderr += String(chunk);
    });
    child.once('error', rejectPromise);
    child.once('close', status => {
      clearTimeout(timer);
      resolvePromise({ status: timedOut ? null : status, stdout, stderr });
    });
    child.stdin.end(input.stdin);
  });
}

function safeBridgeError(message: string): Error {
  // Never expose qlib stderr/stdout (which can contain DSNs, SQL, local paths or
  // provider details) to a guest or a relay log.  Callers receive only a stable
  // error class/message suitable for retry classification.
  return new Error(`[result-bridge] ${message}`);
}

function assertPrivateSnapshot(request: ValidatedResultPublishRequest): void {
  const snapshotRoot = resolve(request.snapshotRoot);
  const requestPath = resolve(request.requestPath);
  const stagingRoot = resolve(request.stagingSnapshotRoot);
  const stagingPath = resolve(request.stagingSnapshotPath);
  const manifestPath = resolve(request.manifestSnapshotPath);
  const requestRel = relative(snapshotRoot, requestPath);
  const stagingRel = relative(stagingRoot, stagingPath);
  const manifestRel = relative(stagingPath, manifestPath);
  if (!requestRel || requestRel === '..' || requestRel.startsWith('../') || isAbsolute(requestRel)
    || !stagingRel || stagingRel === '..' || stagingRel.startsWith('../') || isAbsolute(stagingRel)
    || !manifestRel || manifestRel === '..' || manifestRel.startsWith('../') || isAbsolute(manifestRel)) {
    throw safeBridgeError('host snapshot path is outside its private root');
  }
  const snapshotStat = lstatSync(snapshotRoot);
  const requestStat = lstatSync(requestPath);
  const stagingStat = lstatSync(stagingRoot);
  const stagingPathStat = lstatSync(stagingPath);
  const manifestStat = lstatSync(manifestPath);
  const markerPath = join(stagingRoot, '.botmux-private-staging');
  const markerStat = lstatSync(markerPath);
  if (!snapshotStat.isDirectory() || snapshotStat.isSymbolicLink() || (snapshotStat.mode & 0o777) !== 0o700
    || !requestStat.isFile() || requestStat.isSymbolicLink() || (requestStat.mode & 0o777) !== 0o600
    || !stagingStat.isDirectory() || stagingStat.isSymbolicLink() || (stagingStat.mode & 0o777) !== 0o700
    || !stagingPathStat.isDirectory() || stagingPathStat.isSymbolicLink()
    || !manifestStat.isFile() || manifestStat.isSymbolicLink() || (manifestStat.mode & 0o777) !== 0o600
    || !markerStat.isFile() || markerStat.isSymbolicLink() || (markerStat.mode & 0o777) !== 0o600
    || readFileSync(markerPath, 'utf8') !== 'botmux-private-staging-v1\n') {
    throw safeBridgeError('host snapshot is not private regular data');
  }
}

function parseConsumerOutput(stdout: string, request: ValidatedResultPublishRequest): ResultPublishBridgeResult {
  let parsed: unknown;
  try { parsed = JSON.parse(stdout.trim()); } catch { throw safeBridgeError('consumer returned invalid status'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw safeBridgeError('consumer returned invalid status');
  const row = parsed as Record<string, unknown>;
  // The consumer is allowed to return only a bounded result identity/status
  // projection.  Do not forward arbitrary JSON, formal workflow state, or
  // diagnostics from the Python side.
  const allowed = new Set(['accepted', 'ok', 'registered', 'result_id', 'job_id', 'idempotency_key', 'status']);
  if (Object.keys(row).some(key => !allowed.has(key))) throw safeBridgeError('consumer returned invalid status');
  const accepted = row.accepted === true || row.ok === true || row.registered === true
    || (typeof row.status === 'string' && ['QUEUED', 'ACCEPTED', 'PUBLISHED', 'SUCCEEDED'].includes(row.status.toUpperCase()));
  if (!accepted) throw safeBridgeError('consumer rejected the result');
  const resultIdValue = row.result_id ?? row.job_id;
  const resultId = resultIdValue === undefined ? undefined : typeof resultIdValue === 'string' ? bounded(resultIdValue, 256) : undefined;
  const idempotencyKey = row.idempotency_key === undefined
    ? request.idempotencyKey
    : typeof row.idempotency_key === 'string' && /^[a-f0-9]{64}$/u.test(row.idempotency_key)
      ? row.idempotency_key
      : undefined;
  if ((row.result_id !== undefined || row.job_id !== undefined) && resultId === undefined) throw safeBridgeError('consumer returned invalid result identity');
  if (row.idempotency_key !== undefined && idempotencyKey === undefined) throw safeBridgeError('consumer returned invalid idempotency key');
  if (idempotencyKey !== request.idempotencyKey) throw safeBridgeError('consumer returned mismatched idempotency key');
  const status = row.status === undefined ? undefined : typeof row.status === 'string' ? bounded(row.status, 64) : undefined;
  if (row.status !== undefined && status === undefined) throw safeBridgeError('consumer returned invalid status');
  return { accepted: true, ...(resultId ? { resultId } : {}), ...(idempotencyKey ? { idempotencyKey } : {}), ...(status ? { status } : {}) };
}

export class ResultPublishHostBridge {
  private readonly qlibRoot: string;
  /** Digest captured before the first guest request; source drift fails closed. */
  private readonly qlibDigest: string;
  private readonly dsn: string;
  private readonly trustedArtifactRoot: string;
  private readonly command: string;
  private readonly timeoutMs: number;
  private readonly run: NonNullable<ResultPublishBridgeOptions['run']>;

  constructor(options: ResultPublishBridgeOptions) {
    this.qlibRoot = safeRoot(options.qlibRoot);
    const configuredDigest = safeDigest(options.qlibDigest);
    this.qlibDigest = digestQlibRoot(this.qlibRoot);
    if (configuredDigest && this.qlibDigest !== configuredDigest) {
      throw safeBridgeError('qlib source digest is not authorized');
    }
    this.dsn = options.dsn ?? process.env.QRANT_RESEARCH_DATABASE_URL ?? '';
    if (!this.dsn.trim()) throw safeBridgeError('research database is not configured');
    const artifactRoot = resolve(options.trustedArtifactRoot ?? join(this.qlibRoot, 'data', 'research', 'runs'));
    const artifactParent = dirname(artifactRoot);
    if (!existsSync(artifactParent) || !lstatSync(artifactParent).isDirectory() || lstatSync(artifactParent).isSymbolicLink()) {
      throw safeBridgeError('trusted artifact root is unavailable');
    }
    if (existsSync(artifactRoot)) {
      const artifactStat = lstatSync(artifactRoot);
      if (!artifactStat.isDirectory() || artifactStat.isSymbolicLink()) throw safeBridgeError('trusted artifact root is invalid');
    }
    this.trustedArtifactRoot = artifactRoot;
    this.command = options.command ?? 'uv';
    this.timeoutMs = Math.max(1_000, Math.min(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, 10 * 60_000));
    this.run = options.run ?? defaultRun;
  }

  async submit(input: {
    readonly request: ValidatedResultPublishRequest;
    readonly expectedSessionHash: string;
    readonly expectedOwnerOpenIdHash: string;
  }): Promise<ResultPublishBridgeResult> {
    const request = input.request;
    if (!request.requestPath || !request.stagingSnapshotPath || !request.manifestSnapshotPath || !request.turnId) {
      throw safeBridgeError('result request has no trusted turn snapshot');
    }
    if (digestQlibRoot(this.qlibRoot) !== this.qlibDigest) {
      throw safeBridgeError('qlib source digest changed');
    }
    assertPrivateSnapshot(request);
    if (request.sessionHash !== input.expectedSessionHash || request.ownerOpenIdHash !== input.expectedOwnerOpenIdHash) {
      throw safeBridgeError('result request identity does not match current session');
    }
    if (computeResultPayloadHash(request.stagingSnapshotPath, request.manifestSnapshotPath) !== request.payloadHash) {
      throw safeBridgeError('payload hash does not match snapshot');
    }

    // The qlib consumer may atomically consume its request file.  Give it a
    // disposable copy of the host snapshot, never the guest-writable path.
    const temporaryRequestPath = `${resolve(request.requestPath)}.${randomUUID()}.json`;
    copyFileSync(request.requestPath, temporaryRequestPath, 0);
    chmodSync(temporaryRequestPath, 0o600);
    const body = JSON.stringify({
      // dsn is injected here, from host configuration only. It is absent from
      // the guest envelope and never enters the child environment/argv.
      dsn: this.dsn,
      request_path: temporaryRequestPath,
      staging_path: resolve(request.stagingSnapshotPath),
      manifest_path: resolve(request.manifestSnapshotPath),
      session_hash: request.sessionHash,
      owner_open_id_hash: request.ownerOpenIdHash,
      payload_hash: request.payloadHash,
      manifest_hash: request.manifestHash,
      idempotency_key: request.idempotencyKey,
      capability: request.capability,
      turn_id: request.turnId,
      // This path is fixed and validated by the host constructor.  It is
      // intentionally absent from the guest envelope and never derived from
      // request JSON.
      trusted_artifact_root: this.trustedArtifactRoot,
    });
    const args = this.command === 'uv'
      ? ['run', '--project', this.qlibRoot, 'python', '-c', RESULT_PUBLISH_CONSUMER_SCRIPT]
      : ['-c', RESULT_PUBLISH_CONSUMER_SCRIPT];
    const inherited = process.env;
    const env: NodeJS.ProcessEnv = {
      PATH: inherited.PATH ?? '/usr/bin:/bin',
      HOME: inherited.HOME ?? '/tmp',
      LANG: inherited.LANG ?? 'C.UTF-8',
      LC_ALL: inherited.LC_ALL ?? 'C.UTF-8',
      PYTHONUNBUFFERED: '1',
    };
    try {
      const result = await this.run({
        command: this.command,
        args,
        cwd: this.qlibRoot,
        env,
        stdin: body,
        timeoutMs: this.timeoutMs,
      });
      if (result.status === null) throw safeBridgeError('consumer timed out');
      if (result.status !== 0) throw safeBridgeError('consumer failed');
      return parseConsumerOutput(result.stdout, request);
    } catch (error) {
      if (error instanceof Error && error.message.startsWith('[result-bridge]')) throw error;
      throw safeBridgeError('consumer unavailable');
    } finally {
      try { unlinkSync(temporaryRequestPath); } catch { /* consumer may have renamed it */ }
      try { unlinkSync(`${temporaryRequestPath}.accepted`); } catch { /* already consumed */ }
    }
  }
}

export { ResultPublishHostBridge as ResearchResultPublishHostBridge };
