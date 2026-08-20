/**
 * Per-sandbox-user rootless Podman pod lifecycle.
 *
 * A pod is only a network/process namespace. Session homes, worktrees,
 * credentials, and relay outboxes remain under the existing per-session
 * runtime directory and are never put in a pod-owned volume. The pod's
 * metadata and short-lived session leases live under runtimeRoot so a new
 * worker can recreate (or restart) a missing/stopped pod without losing a
 * session's durable files.
 */

import { spawnSync } from 'node:child_process';
import { Socket } from 'node:net';
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';

import type { PastaNetworkPlan } from './podman-execution.js';

const POD_ROOT_NAME = '.botmux-user-pods';
const LOCK_NAME = '.lock';
const LOCK_TIMEOUT_MS = 5_000;
const LOCK_POLL_MS = 10;
const PODMAN_TIMEOUT_MS = 30_000;

export type PodmanPodStatus = 'missing' | 'created' | 'running' | 'exited' | 'stopped' | 'unknown';

/** Host-owned proxy descriptor. No Clash config, controller secret, or node
 * list enters the guest; the host proxy remains the route authority. */
export interface PodmanGuestProxy {
  /** Dedicated listener is mapped from the host loopback into this address. */
  readonly host: '169.254.1.1';
  readonly httpPort: number;
  readonly socksPort?: number;
  /** Main proxy must keep this live selection; BotMux never touches Clash. */
  readonly selectedRoute: 'USA-08';
  /** Optional stronger probe supplied by the host proxy integration. */
  readonly verify?: () => Promise<void>;
}

/** Host-managed guest route; no Clash config or controller secret enters a pod. */
export const DEFAULT_GUEST_PROXY = {
  host: '169.254.1.1',
  httpPort: 17_890,
  socksPort: 17_890,
  selectedRoute: 'USA-08',
} as const satisfies PodmanGuestProxy;

export interface PodmanPodBinding {
  /** Stable opaque ID assigned by the principal authority; never put in a name. */
  readonly sandboxUserId: string;
  /** Generation is frozen into a session and protects against stale joins. */
  readonly podGeneration: number;
  /** App scope is retained for authorization/audit; it does not split pod identity. */
  readonly larkAppId: string;
  readonly sandboxUserHash: string;
  readonly podName: string;
  readonly metadataRoot: string;
  readonly networkProfile: 'guest' | 'owner-memory';
  readonly guestProxy?: PodmanGuestProxy;
}

export interface PodmanPodState {
  readonly status: PodmanPodStatus;
  readonly podName: string;
  readonly podId?: string;
  readonly error?: string;
  readonly binding: PodmanPodBinding;
}

export interface PodmanUserPodManagerOptions {
  readonly commandRunner?: PodmanPodCommandRunner;
  readonly syncCommandRunner?: PodmanPodSyncCommandRunner;
  readonly hostEnv?: Readonly<Record<string, string | undefined>>;
  readonly now?: () => number;
  readonly pid?: number;
  readonly pidStartTime?: string;
  /** Host Clash/Mihomo endpoint selected by the main proxy. */
  readonly guestProxy?: PodmanGuestProxy;
  /** Require the local endpoint to accept a TCP connection before create. */
  readonly verifyGuestProxy?: boolean;
}

export interface PodmanPodCommandResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly error?: Error;
}

export type PodmanPodCommandRunner = (
  command: string,
  args: readonly string[],
  options: { readonly cwd?: string; readonly env?: Readonly<Record<string, string>>; readonly timeoutMs?: number },
) => Promise<PodmanPodCommandResult> | PodmanPodCommandResult;

export type PodmanPodSyncCommandRunner = (
  command: string,
  args: readonly string[],
  options: { readonly cwd?: string; readonly env?: Readonly<Record<string, string>>; readonly timeoutMs?: number },
) => void;

interface PodMetadata {
  readonly schemaVersion: 1;
  readonly sandboxUserHash: string;
  readonly podGeneration: number;
  readonly podName: string;
  readonly larkAppHash: string;
  readonly networkProfile: 'guest' | 'owner-memory';
  readonly proxyRoute?: 'USA-08';
  readonly createdAt: number;
  readonly updatedAt: number;
}

interface PodLeaseRecord {
  readonly pid: number;
  readonly pidStartTime?: string;
  readonly sessionHash: string;
  readonly createdAt: number;
}

function fail(message: string): never {
  throw new Error(`[podman-pod] ${message}`);
}

function safeText(value: unknown, name: string, max = 256): string {
  if (typeof value !== 'string' || value.trim() === '' || value.length > max || /[\u0000\r\n]/u.test(value)) {
    fail(`${name} must be a non-empty string without NUL/newline`);
  }
  return value.trim();
}

function safeGeneration(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) fail('podGeneration must be a positive integer');
  return value as number;
}

function safePort(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 65_535) {
    fail(`${name} must be a TCP port`);
  }
  return value as number;
}

function normalizeProxy(proxy: PodmanGuestProxy | undefined): PodmanGuestProxy | undefined {
  if (!proxy) return undefined;
  if (proxy.host !== '169.254.1.1') fail('guest proxy host is not allowed');
  const httpPort = safePort(proxy.httpPort, 'guest proxy httpPort');
  const socksPort = proxy.socksPort === undefined ? undefined : safePort(proxy.socksPort, 'guest proxy socksPort');
  if (proxy.selectedRoute !== 'USA-08') fail('guest proxy must use the main proxy USA-08 selection');
  return {
    host: proxy.host,
    httpPort,
    ...(socksPort === undefined ? {} : { socksPort }),
    selectedRoute: proxy.selectedRoute,
    ...(proxy.verify ? { verify: proxy.verify } : {}),
  };
}

function verifyTcpPort(port: number): Promise<void> {
  return new Promise<void>((resolvePromise, reject) => {
    const socket = new Socket();
    const finish = (error?: Error): void => {
      socket.destroy();
      if (error) reject(error); else resolvePromise();
    };
    socket.setTimeout(1_000);
    socket.once('connect', () => finish());
    socket.once('timeout', () => finish(new Error('proxy endpoint timed out')));
    socket.once('error', error => finish(error));
    socket.connect(port, '127.0.0.1');
  });
}

function hashPart(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex').slice(0, 24);
}

function podName(sandboxUserHash: string, generation: number): string {
  // Both pieces are fixed-width/validated, so the name remains well inside
  // Podman's name limit and cannot be confused with a session container.
  return `botmux-user-${sandboxUserHash}-g${generation}`;
}

function processStartTime(pid: number): string | undefined {
  try {
    const body = readFileSync(`/proc/${pid}/stat`, 'utf8');
    const closeParen = body.lastIndexOf(')');
    if (closeParen < 0) return undefined;
    return body.slice(closeParen + 2).trim().split(/\s+/u)[19];
  } catch {
    return undefined;
  }
}

function processIsSame(pid: number, expectedStartTime?: string): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 1) return false;
  try { process.kill(pid, 0); } catch { return false; }
  return !expectedStartTime || processStartTime(pid) === expectedStartTime;
}

function sleepSync(milliseconds: number): void {
  const shared = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(shared, 0, 0, milliseconds);
}

async function sleep(milliseconds: number): Promise<void> {
  await new Promise<void>(resolvePromise => setTimeout(resolvePromise, milliseconds));
}

function ensureDirectory(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  try {
    const stat = lstatSync(path);
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`unsafe pod directory: ${path}`);
  } catch (error) {
    fail(`cannot initialize pod directory: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function atomicWriteJson(path: string, value: unknown): void {
  const temporary = `${path}.tmp-${process.pid}-${Math.random().toString(16).slice(2)}`;
  try {
    writeFileSync(temporary, `${JSON.stringify(value)}\n`, { mode: 0o600, flag: 'wx' });
    renameSync(temporary, path);
  } finally {
    try { unlinkSync(temporary); } catch { /* already renamed */ }
  }
}

function parseLease(path: string): PodLeaseRecord | undefined {
  try {
    const value: unknown = JSON.parse(readFileSync(path, 'utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
    const record = value as Record<string, unknown>;
    if (typeof record.pid !== 'number' || !Number.isSafeInteger(record.pid)
      || typeof record.sessionHash !== 'string' || !/^[0-9a-f]{24}$/u.test(record.sessionHash)
      || typeof record.createdAt !== 'number' || !Number.isFinite(record.createdAt)) return undefined;
    return {
      pid: record.pid,
      ...(typeof record.pidStartTime === 'string' ? { pidStartTime: record.pidStartTime } : {}),
      sessionHash: record.sessionHash,
      createdAt: record.createdAt,
    };
  } catch {
    return undefined;
  }
}

function readLiveLeases(metadataRoot: string): Array<{ path: string; record: PodLeaseRecord }> {
  const leasesRoot = join(metadataRoot, 'leases');
  ensureDirectory(leasesRoot);
  const live: Array<{ path: string; record: PodLeaseRecord }> = [];
  for (const name of readdirSync(leasesRoot).filter(item => item.endsWith('.json'))) {
    const path = join(leasesRoot, name);
    const record = parseLease(path);
    if (!record || !processIsSame(record.pid, record.pidStartTime)) {
      try { unlinkSync(path); } catch { /* another worker reclaimed it */ }
      continue;
    }
    live.push({ path, record });
  }
  return live;
}

function parseLockOwner(path: string): { pid?: number; pidStartTime?: string } | undefined {
  try {
    const value = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
    return {
      ...(typeof value.pid === 'number' ? { pid: value.pid } : {}),
      ...(typeof value.pidStartTime === 'string' ? { pidStartTime: value.pidStartTime } : {}),
    };
  } catch {
    return undefined;
  }
}

function lockIsStale(lockRoot: string): boolean {
  const owner = parseLockOwner(join(lockRoot, 'owner.json'));
  if (owner?.pid) return !processIsSame(owner.pid, owner.pidStartTime);
  // mkdir and owner-file creation are separate syscalls. Give a live owner a
  // short grace period before reclaiming a lock whose owner file is not yet
  // visible, otherwise two workers can both enter the lifecycle critical path.
  try { return Date.now() - lstatSync(lockRoot).mtimeMs > 1_000; } catch { return true; }
}

async function withLock<T>(root: string, fn: () => Promise<T>): Promise<T> {
  ensureDirectory(root);
  const lockRoot = join(root, LOCK_NAME);
  const started = Date.now();
  for (;;) {
    try {
      mkdirSync(lockRoot, { mode: 0o700 });
      try {
        writeFileSync(join(lockRoot, 'owner.json'), JSON.stringify({
          pid: process.pid,
          pidStartTime: processStartTime(process.pid),
        }), { mode: 0o600, flag: 'wx' });
      } catch (error) {
        rmSync(lockRoot, { recursive: true, force: true });
        throw error;
      }
      try { return await fn(); } finally { rmSync(lockRoot, { recursive: true, force: true }); }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      if (lockIsStale(lockRoot)) {
        rmSync(lockRoot, { recursive: true, force: true });
        continue;
      }
      if (Date.now() - started >= LOCK_TIMEOUT_MS) fail('pod lifecycle lock is busy; retry later');
      await sleep(LOCK_POLL_MS);
    }
  }
}

function withLockSync<T>(root: string, fn: () => T): T {
  ensureDirectory(root);
  const lockRoot = join(root, LOCK_NAME);
  const started = Date.now();
  for (;;) {
    try {
      mkdirSync(lockRoot, { mode: 0o700 });
      try {
        writeFileSync(join(lockRoot, 'owner.json'), JSON.stringify({
          pid: process.pid,
          pidStartTime: processStartTime(process.pid),
        }), { mode: 0o600, flag: 'wx' });
      } catch (error) {
        rmSync(lockRoot, { recursive: true, force: true });
        throw error;
      }
      try { return fn(); } finally { rmSync(lockRoot, { recursive: true, force: true }); }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      if (lockIsStale(lockRoot)) {
        rmSync(lockRoot, { recursive: true, force: true });
        continue;
      }
      if (Date.now() - started >= LOCK_TIMEOUT_MS) fail('pod lifecycle lock is busy; retry later');
      sleepSync(LOCK_POLL_MS);
    }
  }
}

function defaultRunner(
  command: string,
  args: readonly string[],
  options: { readonly cwd?: string; readonly env?: Readonly<Record<string, string>>; readonly timeoutMs?: number },
): PodmanPodCommandResult {
  const result = spawnSync(command, [...args], {
    cwd: options.cwd,
    env: options.env ? { ...options.env } : undefined,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: false,
    timeout: options.timeoutMs,
  });
  return {
    status: result.status,
    stdout: typeof result.stdout === 'string' ? result.stdout : '',
    stderr: typeof result.stderr === 'string' ? result.stderr : '',
    error: result.error instanceof Error ? result.error : undefined,
  };
}

function commandDescription(command: string, args: readonly string[]): string {
  return [command, ...args].map(value => JSON.stringify(value)).join(' ');
}

function notFound(result: PodmanPodCommandResult): boolean {
  return /no such pod|no such container|not found|does not exist/iu.test(result.stderr);
}

function parsePodState(raw: string, binding: PodmanPodBinding): PodmanPodState {
  let value: unknown;
  try { value = JSON.parse(raw); } catch { return { status: 'unknown', podName: binding.podName, binding, error: 'Podman returned invalid pod inspect JSON' }; }
  const object = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  const stateObject = object.State && typeof object.State === 'object' ? object.State as Record<string, unknown> : object;
  // Podman versions differ here: some emit `State: {Status: "Running"}`
  // while `pod inspect --format={{json .}}` on this host emits
  // `State: "Running"`. Accept both shapes, but keep unknown states fail-closed.
  const rawStatus = (typeof object.State === 'string'
    ? object.State
    : stateObject.Status ?? stateObject.status ?? '').toString().toLowerCase();
  const status: PodmanPodStatus = rawStatus === 'running'
    ? 'running'
    : rawStatus === 'created'
      ? 'created'
      : rawStatus === 'exited'
        ? 'exited'
        : rawStatus === 'stopped'
          ? 'stopped'
          : rawStatus === '' ? 'unknown' : 'unknown';
  const podId = typeof object.Id === 'string' ? object.Id : typeof object.ID === 'string' ? object.ID : undefined;
  return { status, podName: binding.podName, ...(podId ? { podId } : {}), binding };
}

function parsePodLabels(raw: string): Record<string, string> | undefined {
  try {
    const value: unknown = JSON.parse(raw);
    if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
    const object = value as Record<string, unknown>;
    const config = object.Config && typeof object.Config === 'object' ? object.Config as Record<string, unknown> : object;
    const labels = config.Labels && typeof config.Labels === 'object' ? config.Labels : object.Labels;
    if (!labels || typeof labels !== 'object' || Array.isArray(labels)) return undefined;
    const result: Record<string, string> = {};
    for (const [key, value] of Object.entries(labels)) if (typeof value === 'string') result[key] = value;
    return result;
  } catch {
    return undefined;
  }
}

function validateSessionHash(value: string): string {
  if (!/^[0-9a-f]{24}$/u.test(value)) fail('sessionHash must be a 24-character lowercase hash');
  return value;
}

/**
 * One deterministic rootless pod per sandbox user. The manager is deliberately
 * independent from the principal repository: callers pass the already-frozen
 * sandbox user and generation from Session, and no database lookup happens in
 * this lifecycle layer.
 */
export class PodmanUserPodManager {
  readonly runtimeRoot: string;
  private readonly commandRunner: PodmanPodCommandRunner;
  private readonly syncCommandRunner: PodmanPodSyncCommandRunner;
  private readonly hostEnv: Readonly<Record<string, string>>;
  private readonly now: () => number;
  private readonly pid: number;
  private readonly pidStartTime?: string;
  private readonly guestProxy?: PodmanGuestProxy;
  private readonly verifyGuestProxy: boolean;

  constructor(runtimeRoot: string, options: PodmanUserPodManagerOptions = {}) {
    this.runtimeRoot = resolve(safeText(runtimeRoot, 'runtimeRoot', 4096));
    this.commandRunner = options.commandRunner ?? defaultRunner;
    this.syncCommandRunner = options.syncCommandRunner ?? ((command, args, commandOptions) => {
      spawnSync(command, [...args], {
        cwd: commandOptions.cwd,
        env: commandOptions.env ? { ...commandOptions.env } : undefined,
        encoding: 'utf8',
        stdio: 'ignore',
        shell: false,
        timeout: commandOptions.timeoutMs,
      });
    });
    const inherited = options.hostEnv ?? process.env;
    const env: Record<string, string> = {};
    for (const key of ['PATH', 'HOME', 'XDG_RUNTIME_DIR', 'TMPDIR', 'LANG', 'LC_ALL']) {
      const value = inherited[key];
      if (typeof value === 'string' && value.length > 0) env[key] = value;
    }
    this.hostEnv = env;
    this.now = options.now ?? Date.now;
    this.pid = options.pid ?? process.pid;
    this.pidStartTime = options.pidStartTime ?? processStartTime(this.pid);
    this.guestProxy = normalizeProxy(options.guestProxy);
    this.verifyGuestProxy = options.verifyGuestProxy ?? true;
  }

  binding(input: { readonly larkAppId: string; readonly sandboxUserId: string; readonly podGeneration: number; readonly canOpenMemory: boolean }): PodmanPodBinding {
    const larkAppId = safeText(input.larkAppId, 'larkAppId');
    const sandboxUserId = safeText(input.sandboxUserId, 'sandboxUserId');
    const podGeneration = safeGeneration(input.podGeneration);
    // sandboxUserId is deployment-stable and may be reached through more than
    // one Lark app. App scope is retained on the binding for authorization and
    // audit, but it must not split the user's shared pod.
    const sandboxUserHash = hashPart(sandboxUserId);
    const metadataRoot = join(this.runtimeRoot, POD_ROOT_NAME, sandboxUserHash, `g${podGeneration}`);
    return {
      larkAppId,
      sandboxUserId,
      podGeneration,
      sandboxUserHash,
      podName: podName(sandboxUserHash, podGeneration),
      metadataRoot,
      networkProfile: input.canOpenMemory ? 'owner-memory' : 'guest',
      ...(this.guestProxy && !input.canOpenMemory ? { guestProxy: this.guestProxy } : {}),
    };
  }

  private env(): Readonly<Record<string, string>> { return this.hostEnv; }

  private metadataPath(binding: PodmanPodBinding): string { return join(binding.metadataRoot, 'pod.json'); }

  private async run(args: readonly string[]): Promise<PodmanPodCommandResult> {
    const result = await this.commandRunner('podman', args, { env: this.env(), timeoutMs: PODMAN_TIMEOUT_MS });
    if (result.error) throw result.error;
    return result;
  }

  private runSync(args: readonly string[]): void {
    this.syncCommandRunner('podman', args, { env: this.env(), timeoutMs: PODMAN_TIMEOUT_MS });
  }

  private validateExisting(binding: PodmanPodBinding, raw: string): void {
    const labels = parsePodLabels(raw);
    if (!labels
      || labels['io.botmux.managed'] !== 'true'
      || labels['io.botmux.sandbox-user-hash'] !== binding.sandboxUserHash
      || labels['io.botmux.pod-generation'] !== String(binding.podGeneration)
      || labels['io.botmux.network-profile'] !== binding.networkProfile
      || (binding.guestProxy !== undefined && labels['io.botmux.proxy-route'] !== binding.guestProxy.selectedRoute)
      || (binding.guestProxy === undefined && labels['io.botmux.proxy-route'] !== undefined)) {
      fail(`pod ${binding.podName} exists but is not the expected BotMux user pod`);
    }
  }

  private async verifyProxy(binding: PodmanPodBinding): Promise<void> {
    const proxy = binding.guestProxy;
    if (!proxy) return;
    if (proxy.verify) {
      await proxy.verify();
      return;
    }
    if (this.verifyGuestProxy) await verifyTcpPort(proxy.httpPort);
  }

  private createArgs(binding: PodmanPodBinding, network: PastaNetworkPlan): string[] {
    const proxyNetwork = binding.guestProxy
      ? 'pasta:-T,none,-U,none,--map-host-loopback,169.254.1.1'
      : network.networkOption;
    return [
      'pod',
      'create',
      '--infra=true',
      `--name=${binding.podName}`,
      `--network=${proxyNetwork}`,
      ...network.addHosts.map(host => `--add-host=${host}`),
      '--label=io.botmux.managed=true',
      `--label=io.botmux.sandbox-user-hash=${binding.sandboxUserHash}`,
      `--label=io.botmux.pod-generation=${String(binding.podGeneration)}`,
      `--label=io.botmux.network-profile=${binding.networkProfile}`,
      ...(binding.guestProxy ? [`--label=io.botmux.proxy-route=${binding.guestProxy.selectedRoute}`] : []),
    ];
  }

  private writeMetadata(binding: PodmanPodBinding): void {
    ensureDirectory(binding.metadataRoot);
    atomicWriteJson(this.metadataPath(binding), {
      schemaVersion: 1,
      sandboxUserHash: binding.sandboxUserHash,
      podGeneration: binding.podGeneration,
      podName: binding.podName,
      larkAppHash: hashPart(binding.larkAppId),
      networkProfile: binding.networkProfile,
      ...(binding.guestProxy ? { proxyRoute: binding.guestProxy.selectedRoute } : {}),
      createdAt: this.now(),
      updatedAt: this.now(),
    } satisfies PodMetadata);
  }

  /** Create/restart the exact generation. Safe when many workers race. */
  async ensure(binding: PodmanPodBinding, network: PastaNetworkPlan): Promise<PodmanPodState> {
    return withLock(join(this.runtimeRoot, POD_ROOT_NAME), async () => {
      await this.verifyProxy(binding);
      ensureDirectory(binding.metadataRoot);
      let inspect = await this.run(['pod', 'inspect', '--format={{json .}}', binding.podName]);
      if (inspect.status === 0) {
        this.validateExisting(binding, inspect.stdout);
        const current = parsePodState(inspect.stdout.trim(), binding);
        if (current.status === 'created' || current.status === 'stopped' || current.status === 'exited') {
          const started = await this.run(['pod', 'start', binding.podName]);
          if (started.status !== 0 && !notFound(started)) {
            fail(`could not start ${binding.podName}: ${started.stderr.trim() || `exit ${String(started.status)}`}`);
          }
          inspect = await this.run(['pod', 'inspect', '--format={{json .}}', binding.podName]);
          if (inspect.status === 0) this.validateExisting(binding, inspect.stdout);
        }
        this.writeMetadata(binding);
        return parsePodState(inspect.stdout.trim(), binding);
      }
      if (!notFound(inspect)) {
        fail(`${commandDescription('podman', ['pod', 'inspect', binding.podName])} failed: ${inspect.stderr.trim() || `exit ${String(inspect.status)}`}`);
      }
      const created = await this.run(this.createArgs(binding, network));
      if (created.status !== 0 && !/already exists/iu.test(created.stderr)) {
        fail(`could not create ${binding.podName}: ${created.stderr.trim() || `exit ${String(created.status)}`}`);
      }
      inspect = await this.run(['pod', 'inspect', '--format={{json .}}', binding.podName]);
      if (inspect.status !== 0) fail(`pod ${binding.podName} was not inspectable after creation`);
      this.validateExisting(binding, inspect.stdout);
      this.writeMetadata(binding);
      return parsePodState(inspect.stdout.trim(), binding);
    });
  }

  async inspect(binding: PodmanPodBinding): Promise<PodmanPodState> {
    const result = await this.run(['pod', 'inspect', '--format={{json .}}', binding.podName]);
    if (result.status !== 0 && notFound(result)) return { status: 'missing', podName: binding.podName, binding };
    if (result.status !== 0) return { status: 'unknown', podName: binding.podName, binding, error: result.stderr.trim() || `exit ${String(result.status)}` };
    this.validateExisting(binding, result.stdout);
    return parsePodState(result.stdout.trim(), binding);
  }

  /** Stop the pod only when no live session worker still owns it. */
  async stopIfIdle(binding: PodmanPodBinding): Promise<void> {
    await withLock(join(this.runtimeRoot, POD_ROOT_NAME), async () => {
      if (readLiveLeases(binding.metadataRoot).length > 0) return;
      const result = await this.run(['pod', 'stop', '--time', '10', binding.podName]);
      if (result.status !== 0 && !notFound(result)) {
        fail(`could not stop ${binding.podName}: ${result.stderr.trim() || `exit ${String(result.status)}`}`);
      }
    });
  }

  stopIfIdleSync(binding: PodmanPodBinding): void {
    withLockSync(join(this.runtimeRoot, POD_ROOT_NAME), () => {
      if (readLiveLeases(binding.metadataRoot).length > 0) return;
      this.runSync(['pod', 'stop', '--time', '10', binding.podName]);
    });
  }

  /** Remove the pod, preserving all session runtime directories and metadata. */
  async remove(binding: PodmanPodBinding, options: { readonly force?: boolean } = {}): Promise<void> {
    await withLock(join(this.runtimeRoot, POD_ROOT_NAME), async () => {
      const live = readLiveLeases(binding.metadataRoot);
      if (live.length > 0 && options.force !== true) fail(`pod ${binding.podName} still has live sessions`);
      const result = await this.run(['pod', 'rm', ...(options.force ? ['--force'] : []), binding.podName]);
      if (result.status !== 0 && !notFound(result)) {
        fail(`could not remove ${binding.podName}: ${result.stderr.trim() || `exit ${String(result.status)}`}`);
      }
      // Metadata is intentionally retained: it proves which generation must
      // be recreated and lets a cold worker reuse the existing session dirs.
    });
  }

  /** Reserve one session slot in this user's pod. */
  acquireSession(binding: PodmanPodBinding, sessionHash: string): () => void {
    validateSessionHash(sessionHash);
    return withLockSync(join(this.runtimeRoot, POD_ROOT_NAME), () => {
      ensureDirectory(binding.metadataRoot);
      const live = readLiveLeases(binding.metadataRoot);
      const existing = live.find(item => item.record.sessionHash === sessionHash);
      if (existing) fail(`session ${sessionHash} already owns pod ${binding.podName}`);
      const path = join(binding.metadataRoot, 'leases', `${sessionHash}.json`);
      atomicWriteJson(path, {
        pid: this.pid,
        ...(this.pidStartTime ? { pidStartTime: this.pidStartTime } : {}),
        sessionHash,
        createdAt: this.now(),
      } satisfies PodLeaseRecord);
      let released = false;
      return (): void => {
        if (released) return;
        released = true;
        withLockSync(join(this.runtimeRoot, POD_ROOT_NAME), () => {
          try { unlinkSync(path); } catch { /* idempotent */ }
        });
      };
    });
  }

  /** Release all dead-worker leases and optionally stop/remove idle pods. */
  async reclaimStale(binding: PodmanPodBinding, options: { readonly removeIdle?: boolean } = {}): Promise<void> {
    await withLock(join(this.runtimeRoot, POD_ROOT_NAME), async () => {
      const live = readLiveLeases(binding.metadataRoot);
      if (live.length > 0 || options.removeIdle !== true) return;
      const stopped = await this.run(['pod', 'stop', '--time', '10', binding.podName]);
      if (stopped.status !== 0 && !notFound(stopped)) return;
      const removed = await this.run(['pod', 'rm', '--force', binding.podName]);
      if (removed.status !== 0 && !notFound(removed)) return;
    });
  }
}

export function createPodmanUserPodManager(
  runtimeRoot: string,
  options?: PodmanUserPodManagerOptions,
): PodmanUserPodManager {
  return new PodmanUserPodManager(runtimeRoot, {
    ...options,
    guestProxy: options?.guestProxy ?? DEFAULT_GUEST_PROXY,
  });
}

export const PODMAN_USER_POD_ROOT_NAME = POD_ROOT_NAME;
