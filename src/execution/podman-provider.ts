/**
 * Side-effecting Podman lifecycle for the pure T4 execution plan.
 *
 * The provider owns the small amount of filesystem and process plumbing that
 * turns a validated plan into a launch specification.  It deliberately does
 * not know about the daemon, a database, or a CLI adapter: callers hand it a
 * frozen principal/credential binding and a fully-built argv from the adapter.
 * Secrets are accepted only by launch(), kept in the returned process env, and
 * never become part of a Podman argv or a runtime file.
 */

import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import {
  assertCredentialCompatible,
  buildCredentialInjectionPlan,
  buildPastaNetworkPlan,
  buildPodmanMountPlan,
  buildSessionRuntimePaths,
  fixedBotCliId,
  materializeCredentialEnvironment,
  parsePodmanExecutionConfig,
  type CredentialInjectionPlan,
  type PodmanCliId,
  type PodmanCredentialKind,
  type PodmanExecutionConfig,
  type PodmanMountPlan,
  type SessionRuntimePaths,
} from './podman-execution.js';

const CONTAINER_HOME = '/home/dev';
const CONTAINER_WORKSPACE = '/workspace';
const CONTAINER_WORKDIR = '/workspace/analyze';
const CONTAINER_SESSION_HOME = '/home/dev/.agent';
const CONTAINER_DATA_ROOT = '/shared/quant-data';
const CONTAINER_KNOWLEDGE_ROOT = '/knowledge/investment-books';
const CONTAINER_OUTBOX_ROOT = '/session/outbox';
const DEFAULT_PATH = '/home/dev/.local/bin:/opt/agent-sandbox/bin:/usr/local/bin:/usr/bin:/bin';
const PODMAN_TIMEOUT_MS = 30_000;
const GIT_TIMEOUT_MS = 60_000;
const CLONE_DIRECTORY = 'analyze';

const CLI_BINARIES: Record<PodmanCliId, string> = {
  codex: 'codex',
  'claude-code': 'claude',
  pi: 'pi',
  opencode: 'opencode',
};

/** The image entrypoint owns this fixed binary; no host executable lookup is needed. */
export function fixedPodmanCliBinary(cliId: string): string {
  return CLI_BINARIES[fixedBotCliId({ cliId })];
}

export interface PrincipalBinding {
  readonly larkAppId: string;
  /** T6 may deserialize either spelling; the normalized key is never exposed. */
  readonly openId?: string;
  readonly open_id?: string;
  /** Missing means enabled. An explicit false is a fail-closed disable. */
  readonly enabled?: boolean;
  readonly canOpenMemory?: boolean;
  readonly can_openmemory?: boolean;
  /** Non-secret frozen metadata written by the T6 principal boundary. */
  readonly cliId?: string;
  readonly credentialKind?: string;
  readonly credentialVersion?: number;
  readonly ownerOpenId?: string;
}

/** Durable, non-secret credential metadata supplied by the future T6 layer. */
export interface CredentialBinding {
  readonly kind?: PodmanCredentialKind | string;
  /** Compatibility spelling for the T6 credential row. */
  readonly credentialKind?: PodmanCredentialKind | string;
  /** T6 may call this field `version` or `credentialVersion`. */
  readonly version?: number;
  readonly credentialVersion?: number;
  readonly baseUrl?: string;
  readonly model?: string;
}
export type PodmanCredentialBinding = CredentialBinding;

export interface PodmanPrepareInput {
  readonly sessionId: string;
  readonly cliId: string;
  readonly expectedLarkAppId?: string;
  readonly expectedOwnerOpenId?: string;
  readonly principalBinding?: PrincipalBinding;
  readonly credentialBinding?: CredentialBinding;
}

export interface PodmanCliLaunchSpec {
  readonly cliId: string;
  readonly bin: string;
  readonly args: readonly string[];
  /** The API secret is transient launch input, never a durable binding. */
  readonly credentialSecret?: string;
  /** Non-secret botmux routing context; arbitrary environment is rejected. */
  readonly runtimeEnv?: Readonly<Record<string, string | undefined>>;
}
export type CliLaunchSpec = PodmanCliLaunchSpec;

export interface TranscriptPathMap {
  readonly hostSessionHome: string;
  readonly containerSessionHome: typeof CONTAINER_SESSION_HOME;
  readonly hostTranscriptRoot: string;
  readonly containerTranscriptRoot: typeof CONTAINER_HOME;
  readonly hostWorkspaceRoot: string;
  readonly containerWorkspaceRoot: typeof CONTAINER_WORKSPACE;
}

export interface PreparedExecution {
  readonly config: PodmanExecutionConfig;
  readonly sessionId: string;
  readonly runtime: SessionRuntimePaths;
  readonly cliId: PodmanCliId;
  readonly credential: CredentialInjectionPlan;
  readonly mounts: readonly PodmanMountPlan[];
  readonly network: ReturnType<typeof buildPastaNetworkPlan>;
  readonly hostWorkingDir: string;
  readonly containerWorkingDir: typeof CONTAINER_WORKDIR;
  readonly transcriptPaths: TranscriptPathMap;
  readonly hostUid: number;
  readonly hostGid: number;
}
export type PreparedPodmanExecution = PreparedExecution;

export interface ContainerLaunchSpec {
  readonly bin: 'podman';
  readonly args: readonly string[];
  /** Host cwd for the Podman client; the CLI cwd is --workdir in the container. */
  readonly cwd: string;
  /** Explicit allow-listed environment. It is not derived from process.env. */
  readonly env: Readonly<Record<string, string>>;
  readonly containerName: string;
  readonly cliId: PodmanCliId;
  readonly runtime: SessionRuntimePaths;
  readonly transcriptPaths: TranscriptPathMap;
}

export type RuntimeStatus = 'missing' | 'created' | 'running' | 'exited' | 'stopped' | 'unknown';

export interface RuntimeState {
  readonly status: RuntimeStatus;
  readonly containerName: string;
  readonly containerId?: string;
  readonly exitCode?: number;
  readonly error?: string;
}

export interface PodmanCommandResult {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly error?: Error;
}

export type PodmanCommandRunner = (
  command: string,
  args: readonly string[],
  options: { readonly cwd?: string; readonly env?: Readonly<Record<string, string>>; readonly timeoutMs?: number },
) => Promise<PodmanCommandResult> | PodmanCommandResult;

/** Synchronous, last-resort stop hook used from Node's process-exit event. */
export type PodmanSyncCommandRunner = (
  command: string,
  args: readonly string[],
  options: { readonly cwd?: string; readonly env?: Readonly<Record<string, string>>; readonly timeoutMs?: number },
) => void;

export interface PodmanExecutionProviderOptions {
  readonly commandRunner?: PodmanCommandRunner;
  readonly syncCommandRunner?: PodmanSyncCommandRunner;
  /** Unit tests can inject a fake runner without probing a local image store. */
  readonly checkImage?: boolean;
  readonly hostUid?: number;
  readonly hostGid?: number;
  /** Minimal host environment used by the Podman client itself. */
  readonly hostEnv?: Readonly<Record<string, string | undefined>>;
}

function fail(message: string): never {
  throw new Error(`[podman] ${message}`);
}

function nonEmpty(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.trim() === '' || /[\u0000\r\n]/u.test(value)) {
    fail(`${name} must be a non-empty string without NUL/newline`);
  }
  return value.trim();
}

function safeArgument(value: unknown, name: string): string {
  const result = nonEmpty(value, name);
  if (result.includes('\u0000')) fail(`${name} contains NUL`);
  return result;
}

function safeSessionId(value: unknown): string {
  const sessionId = nonEmpty(value, 'sessionId');
  if (sessionId.length > 256) fail('sessionId is too long');
  return sessionId;
}

function normalizedOpenId(binding: PrincipalBinding): string {
  const camel = binding.openId;
  const snake = binding.open_id;
  if (camel !== undefined && snake !== undefined && camel !== snake) {
    fail('principalBinding.openId and open_id conflict');
  }
  return nonEmpty(camel ?? snake, 'principalBinding.openId');
}

function normalizedMemoryCapability(binding: PrincipalBinding): boolean {
  const camel = binding.canOpenMemory;
  const snake = binding.can_openmemory;
  if (camel !== undefined && typeof camel !== 'boolean') fail('principalBinding.canOpenMemory must be boolean');
  if (snake !== undefined && typeof snake !== 'boolean') fail('principalBinding.can_openmemory must be boolean');
  if (camel !== undefined && snake !== undefined && camel !== snake) fail('principal memory capability conflicts');
  return camel ?? snake ?? false;
}

function validatePrincipal(binding: PrincipalBinding | undefined, cliId?: PodmanCliId): {
  readonly larkAppId: string;
  readonly openId: string;
  readonly canOpenMemory: boolean;
  readonly ownerOpenId?: string;
} {
  if (!binding || typeof binding !== 'object') fail('principal binding is required; database lookup is not allowed here');
  if (binding.enabled !== undefined && typeof binding.enabled !== 'boolean') {
    fail('principalBinding.enabled must be boolean');
  }
  if (binding.enabled === false) fail('principal binding is disabled');
  const larkAppId = nonEmpty(binding.larkAppId, 'principalBinding.larkAppId');
  const openId = normalizedOpenId(binding);
  if (cliId !== undefined && binding.cliId !== undefined && binding.cliId !== cliId) {
    fail('principalBinding.cliId does not match the fixed bot harness');
  }
  if (binding.credentialVersion !== undefined
    && (!Number.isSafeInteger(binding.credentialVersion) || binding.credentialVersion <= 0)) {
    fail('principalBinding.credentialVersion must be a positive integer');
  }
  const ownerOpenId = binding.ownerOpenId === undefined
    ? undefined
    : nonEmpty(binding.ownerOpenId, 'principalBinding.ownerOpenId');
  return { larkAppId, openId, canOpenMemory: normalizedMemoryCapability(binding), ...(ownerOpenId ? { ownerOpenId } : {}) };
}

function validateCredential(binding: CredentialBinding | undefined, cliId: PodmanCliId): CredentialBinding & {
  readonly kind: string;
  readonly version: number;
} {
  if (!binding || typeof binding !== 'object') fail('credential binding is required; database lookup is not allowed here');
  if (binding.kind !== undefined && binding.credentialKind !== undefined && binding.kind !== binding.credentialKind) {
    fail('credentialBinding.kind and credentialKind conflict');
  }
  const kind = nonEmpty(binding.kind ?? binding.credentialKind, 'credentialBinding.kind');
  if (binding.version !== undefined && binding.credentialVersion !== undefined
    && binding.version !== binding.credentialVersion) {
    fail('credentialBinding.version and credentialVersion conflict');
  }
  const version = binding.version ?? binding.credentialVersion;
  if (typeof version !== 'number' || !Number.isSafeInteger(version) || version <= 0) {
    fail('credentialBinding.version must be a positive integer');
  }
  const normalizedVersion = version;
  assertCredentialCompatible(cliId, kind);
  return { ...binding, kind, credentialKind: kind, version: normalizedVersion };
}

function defaultRunner(command: string, args: readonly string[], options: {
  readonly cwd?: string;
  readonly env?: Readonly<Record<string, string>>;
  readonly timeoutMs?: number;
}): PodmanCommandResult {
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

async function runCommand(
  runner: PodmanCommandRunner,
  command: string,
  args: readonly string[],
  options: { readonly cwd?: string; readonly env?: Readonly<Record<string, string>>; readonly timeoutMs?: number },
): Promise<PodmanCommandResult> {
  const result = await runner(command, args, options);
  if (result.error) throw result.error;
  return result;
}

function commandDescription(command: string, args: readonly string[]): string {
  return [command, ...args].map(value => JSON.stringify(value)).join(' ');
}

async function requireCommandSuccess(
  runner: PodmanCommandRunner,
  command: string,
  args: readonly string[],
  options: { readonly cwd?: string; readonly env?: Readonly<Record<string, string>>; readonly timeoutMs?: number },
): Promise<PodmanCommandResult> {
  const result = await runCommand(runner, command, args, options);
  if (result.status !== 0) {
    const detail = result.stderr.trim() || result.stdout.trim() || `exit ${String(result.status)}`;
    fail(`${commandDescription(command, args)} failed: ${detail}`);
  }
  return result;
}

function ensureDirectory(path: string, mode = 0o700): void {
  const absolute = resolve(path);
  let cursor = '/';
  for (const segment of absolute.split('/').filter(Boolean)) {
    cursor = join(cursor, segment);
    let stat: ReturnType<typeof lstatSync>;
    try {
      stat = lstatSync(cursor);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      mkdirSync(cursor, { mode });
      stat = lstatSync(cursor);
    }
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      fail(`runtime path is not a real directory: ${cursor}`);
    }
  }
  chmodSync(absolute, mode);
}

function requireSourceDirectory(path: string, label: string): void {
  const absolute = resolve(path);
  let cursor = '/';
  const segments = absolute.split('/').filter(Boolean);
  for (const [index, segment] of segments.entries()) {
    cursor = join(cursor, segment);
    let stat: ReturnType<typeof lstatSync>;
    try {
      stat = lstatSync(cursor);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') fail(`${label} does not exist: ${path}`);
      throw error;
    }
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      fail(`${label} must be a real directory: ${index === segments.length - 1 ? path : cursor}`);
    }
  }
}

/** The nested RW bind is a mountpoint, never a fallback data directory. */
function ensureEmptyStagingMountpoint(path: string, label: string): void {
  const absolute = resolve(path);
  let stat: ReturnType<typeof lstatSync>;
  try {
    stat = lstatSync(absolute);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    mkdirSync(absolute, { mode: 0o755 });
    stat = lstatSync(absolute);
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) fail(`${label} must be a real directory mountpoint`);
  if (readdirSync(absolute).length > 0) fail(`${label} must be empty; it is only a writable mountpoint`);
  chmodSync(absolute, 0o755);
}

function requireValidCodexAuthFile(path: string): void {
  let stat: ReturnType<typeof lstatSync>;
  try {
    stat = lstatSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      fail(`Codex auth.json must already exist: ${path}`);
    }
    throw error;
  }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    fail(`Codex auth.json is not a regular file: ${path}`);
  }
  // The auth file is a credential boundary. Do not repair its mode here:
  // callers must provision it owner-only before prepare() is allowed to bind it.
  if ((stat.mode & 0o077) !== 0 || (stat.mode & 0o400) === 0) {
    fail(`Codex auth.json must be readable by the owner only: ${path}`);
  }
  const body = readFileSync(path, 'utf8');
  if (body.trim() === '') fail(`Codex auth.json must be non-empty: ${path}`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    fail(`Codex auth.json must contain valid JSON: ${path}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
    || Object.keys(parsed as Record<string, unknown>).length === 0) {
    fail(`Codex auth.json must contain a non-empty JSON object: ${path}`);
  }
}

function assertSafeMountPath(path: string): void {
  if (!path.startsWith('/') || path.includes('\u0000') || path.includes('\r') || path.includes('\n')) {
    fail(`unsafe mount path: ${path}`);
  }
}

function mountArgument(mount: PodmanMountPlan): string {
  assertSafeMountPath(mount.source);
  const mode = mount.mode;
  // T4's sources are canonical POSIX paths. Reject commas rather than trying
  // to guess Podman's mount escaping grammar and accidentally changing a bind.
  if (mount.source.includes(',') || mount.target.includes(',')) fail('mount paths may not contain commas');
  return `type=bind,src=${mount.source},dst=${mount.target},${mode}`;
}

function cliHarness(cliId: PodmanCliId): string {
  return cliId === 'claude-code' ? 'claude' : cliId;
}

function checkCliLaunch(prepared: PreparedExecution, launch: PodmanCliLaunchSpec): string[] {
  if (launch.cliId !== prepared.cliId) fail(`cliId mismatch: bot is ${prepared.cliId}, launch is ${launch.cliId}`);
  const expected = CLI_BINARIES[prepared.cliId];
  const actual = safeArgument(launch.bin, 'cliLaunchSpec.bin').split('/').pop();
  if (actual !== expected) fail(`adapter binary ${actual} is not the fixed ${expected} for ${prepared.cliId}`);
  if (!Array.isArray(launch.args)) fail('cliLaunchSpec.args must be an array');
  return launch.args.map((arg, index) => safeArgument(arg, `cliLaunchSpec.args[${index}]`));
}

function validateRuntimeEnvironment(input: PodmanCliLaunchSpec['runtimeEnv']): Record<string, string> {
  const output: Record<string, string> = {};
  for (const [key, raw] of Object.entries(input ?? {})) {
    if (!RUNTIME_ENV_KEYS.has(key)) fail(`cliLaunchSpec.runtimeEnv.${key} is not allow-listed`);
    if (raw === undefined) continue;
    output[key] = safeArgument(raw, `cliLaunchSpec.runtimeEnv.${key}`);
  }
  return output;
}

function canonicalPreparedConfig(config: PodmanExecutionConfig): PodmanExecutionConfig {
  return parsePodmanExecutionConfig(config, 'config');
}

function assertPrepared(prepared: PreparedExecution, expectedConfig?: PodmanExecutionConfig): void {
  if (!prepared || typeof prepared !== 'object') fail('prepared execution is required');
  const config = canonicalPreparedConfig(prepared.config);
  if (config.image !== prepared.config.image || config.runtimeRoot !== prepared.config.runtimeRoot) {
    fail('prepared execution config is not canonical');
  }
  if (expectedConfig) {
    const expected = canonicalPreparedConfig(expectedConfig);
    if (JSON.stringify(config) !== JSON.stringify(expected)) {
      fail('prepared execution belongs to a different provider config');
    }
  }
  safeSessionId(prepared.sessionId);
  if (!prepared.runtime.containerName.startsWith('botmux-')) fail('prepared runtime has an invalid container name');
  if (prepared.hostWorkingDir !== join(prepared.runtime.workspaceRoot, CLONE_DIRECTORY)) {
    fail('prepared host working directory is not the canonical clone path');
  }
  if (prepared.containerWorkingDir !== CONTAINER_WORKDIR) fail('prepared container working directory is not fixed');
  const expectedMounts = buildPodmanMountPlan(config, prepared.runtime, prepared.credential);
  if (JSON.stringify(expectedMounts) !== JSON.stringify(prepared.mounts)) fail('prepared mounts do not match the T4 allow-list');
  const expectedNetwork = buildPastaNetworkPlan(prepared.network.canOpenMemory);
  if (JSON.stringify(expectedNetwork) !== JSON.stringify(prepared.network)) fail('prepared network does not match the T4 allow-list');
  const expectedTranscriptPaths: TranscriptPathMap = {
    hostSessionHome: prepared.runtime.homeRoot,
    containerSessionHome: CONTAINER_SESSION_HOME,
    hostTranscriptRoot: prepared.runtime.homeRoot,
    containerTranscriptRoot: CONTAINER_HOME,
    hostWorkspaceRoot: prepared.runtime.workspaceRoot,
    containerWorkspaceRoot: CONTAINER_WORKSPACE,
  };
  if (JSON.stringify(expectedTranscriptPaths) !== JSON.stringify(prepared.transcriptPaths)) {
    fail('prepared transcript paths are not canonical');
  }
}

function parseInspectState(raw: string, containerName: string): RuntimeState {
  let value: unknown;
  try { value = JSON.parse(raw); } catch { return { status: 'unknown', containerName, error: 'Podman returned invalid inspect JSON' }; }
  const state = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  const statusRaw = typeof state.Status === 'string' ? state.Status.toLowerCase() : '';
  const status: RuntimeStatus = statusRaw === 'running'
    ? 'running'
    : statusRaw === 'created'
      ? 'created'
      : statusRaw === 'exited'
        ? 'exited'
        : statusRaw === 'stopped'
          ? 'stopped'
          : 'unknown';
  const exitCode = typeof state.ExitCode === 'number' ? state.ExitCode : undefined;
  const containerId = typeof state.ContainerID === 'string'
    ? state.ContainerID
    : typeof state.Id === 'string' ? state.Id : undefined;
  return { status, containerName, ...(containerId ? { containerId } : {}), ...(exitCode !== undefined ? { exitCode } : {}) };
}

const prepareLocks = new Map<string, Promise<PreparedExecution>>();
const RUNTIME_ENV_KEYS = new Set([
  'BOTMUX_CHAT_ID',
  'BOTMUX_CHAT_TYPE',
  'BOTMUX_LARK_APP_ID',
  'BOTMUX_ROOT_MESSAGE_ID',
  'BOTMUX_TURN_ID',
  'BOTMUX_DISPATCH_ATTEMPT',
  'BOTMUX_API_ONLY',
  'BOTMUX_BRAND',
  'BOTMUX_USAGE_DISPLAY',
  'BOTMUX_DAEMON_IPC_PORT',
  'BOTMUX_SESSION_SCOPE',
  // qlib's filesystem-only submit command needs explicit session envelope
  // values.  These are hashes/paths/capability values minted by botmux; no
  // arbitrary host environment is forwarded into the container.
  'QRANT_SESSION_STAGING_ROOT',
  'QRANT_SESSION_OUTBOX_DIR',
  'QRANT_SESSION_HASH',
  'QRANT_OWNER_OPEN_ID_HASH',
]);

/**
 * Podman lifecycle implementation. A provider instance is tied to one frozen
 * execution config; principal and credential bindings are supplied per
 * session and are never resolved from disk or a database here.
 */
export class PodmanExecutionProvider {
  readonly config: PodmanExecutionConfig;
  private readonly runner: PodmanCommandRunner;
  private readonly syncCommandRunner: PodmanSyncCommandRunner;
  private readonly checkImage: boolean;
  private readonly hostUid: number;
  private readonly hostGid: number;
  private readonly hostEnv: Readonly<Record<string, string>>;

  constructor(config: PodmanExecutionConfig, options: PodmanExecutionProviderOptions = {}) {
    this.config = canonicalPreparedConfig(config);
    this.runner = options.commandRunner ?? defaultRunner;
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
    this.checkImage = options.checkImage ?? true;
    const uid = options.hostUid ?? process.getuid?.() ?? 0;
    const gid = options.hostGid ?? process.getgid?.() ?? 0;
    if (!Number.isSafeInteger(uid) || uid < 0 || !Number.isSafeInteger(gid) || gid < 0) {
      fail('host uid/gid are invalid');
    }
    if (uid === 0) fail('Podman execution requires a non-root host uid');
    this.hostUid = uid;
    this.hostGid = gid;
    const inheritedHostEnv = options.hostEnv ?? process.env;
    const clientEnv: Record<string, string> = {};
    for (const key of ['PATH', 'HOME', 'XDG_RUNTIME_DIR', 'TMPDIR', 'LANG', 'LC_ALL']) {
      const value = inheritedHostEnv[key];
      if (typeof value === 'string' && value.length > 0) clientEnv[key] = value;
    }
    this.hostEnv = clientEnv;
  }

  async prepare(input: PodmanPrepareInput): Promise<PreparedExecution> {
    const sessionId = safeSessionId(input.sessionId);
    const cliId = fixedBotCliId({ cliId: input.cliId });
    const principal = validatePrincipal(input.principalBinding, cliId);
    if (input.expectedLarkAppId !== undefined
      && principal.larkAppId !== nonEmpty(input.expectedLarkAppId, 'expectedLarkAppId')) {
      fail('principal binding belongs to a different larkAppId');
    }
    if (input.expectedOwnerOpenId !== undefined
      && principal.openId !== nonEmpty(input.expectedOwnerOpenId, 'expectedOwnerOpenId')
      && principal.ownerOpenId !== nonEmpty(input.expectedOwnerOpenId, 'expectedOwnerOpenId')) {
      fail('principal binding does not match the frozen topic owner');
    }
    const credentialBinding = validateCredential(input.credentialBinding, cliId);
    if (input.principalBinding?.credentialKind !== undefined
      && input.principalBinding.credentialKind !== credentialBinding.kind) {
      fail('principal and credential bindings disagree on credential kind');
    }
    if (input.principalBinding?.credentialVersion !== undefined
      && input.principalBinding.credentialVersion !== credentialBinding.version) {
      fail('principal and credential bindings disagree on credential version');
    }
    const runtime = buildSessionRuntimePaths(this.config, principal, sessionId);
    const lockKey = `${this.config.runtimeRoot}/${runtime.principalHash}/${runtime.sessionHash}`;
    const previous = prepareLocks.get(lockKey) ?? Promise.resolve(undefined as unknown as PreparedExecution);
    const current = previous.then(async () => {
      const credential = buildCredentialInjectionPlan({
        cliId,
        credentialKind: credentialBinding.kind,
        credentialVersion: credentialBinding.version,
        sessionHome: runtime.homeRoot,
        authPath: runtime.codexAuthPath,
        baseUrl: credentialBinding.baseUrl,
        model: credentialBinding.model,
      });
      const mounts = buildPodmanMountPlan(this.config, runtime, credential);
      const network = buildPastaNetworkPlan(principal.canOpenMemory);
      requireSourceDirectory(this.config.sourceRepo, 'sourceRepo');
      requireSourceDirectory(this.config.dataRoot, 'dataRoot');
      // Podman must find the nested target before the parent read-only bind is
      // applied. This empty, real directory is only a mountpoint in the
      // central tree; all writes go to runtime.stagingRoot below.
      ensureEmptyStagingMountpoint(join(this.config.dataRoot, 'staging'), 'dataRoot/staging mountpoint');
      requireSourceDirectory(this.config.knowledgeRoot, 'knowledgeRoot');
      if (this.checkImage) {
        await requireCommandSuccess(this.runner, 'podman', ['image', 'exists', this.config.image], { timeoutMs: PODMAN_TIMEOUT_MS });
      }
      ensureDirectory(this.config.runtimeRoot);
      ensureDirectory(runtime.principalRoot);
      ensureDirectory(runtime.sessionRoot);
      ensureDirectory(runtime.workspaceRoot);
      ensureDirectory(runtime.homeRoot);
      ensureDirectory(join(runtime.homeRoot, '.agent'));
      // The leaf auth bind is applied after the home bind. Podman requires the
      // destination parent to exist in the home source, otherwise it cannot
      // resolve /home/dev/.codex/auth.json once /home/dev is over-mounted.
      if (cliId === 'codex') ensureDirectory(join(runtime.homeRoot, '.codex'));
      ensureDirectory(runtime.outboxRoot);
      // qlib/data is linked to the read-only central lake. Keep session
      // staging outside dataRoot and overlay only this leaf as a writable
      // nested bind at /shared/quant-data/staging.
      ensureDirectory(runtime.stagingRoot);
      ensureDirectory(runtime.runtimeStateRoot);
      ensureDirectory(runtime.credentialCacheRoot);
      ensureDirectory(runtime.codexCredentialRoot);
      if (credential.credentialKind === 'codex_chatgpt') requireValidCodexAuthFile(runtime.codexAuthPath);
      const hostWorkingDir = join(runtime.workspaceRoot, CLONE_DIRECTORY);
      await this.prepareClone(hostWorkingDir);
      if (credential.providerConfig) {
        ensureProviderConfig(credential.providerConfig.path, credential.providerConfig);
      }
      const prepared: PreparedExecution = {
        config: this.config,
        sessionId,
        runtime,
        cliId,
        credential,
        mounts,
        network,
        hostWorkingDir,
        containerWorkingDir: CONTAINER_WORKDIR,
        transcriptPaths: {
          hostSessionHome: runtime.homeRoot,
          containerSessionHome: CONTAINER_SESSION_HOME,
          hostTranscriptRoot: runtime.homeRoot,
          containerTranscriptRoot: CONTAINER_HOME,
          hostWorkspaceRoot: runtime.workspaceRoot,
          containerWorkspaceRoot: CONTAINER_WORKSPACE,
        },
        hostUid: this.hostUid,
        hostGid: this.hostGid,
      };
      assertPrepared(prepared, this.config);
      return prepared;
    });
    prepareLocks.set(lockKey, current);
    try {
      return await current;
    } finally {
      if (prepareLocks.get(lockKey) === current) prepareLocks.delete(lockKey);
    }
  }

  private async prepareClone(clonePath: string): Promise<void> {
    let existing: ReturnType<typeof lstatSync> | undefined;
    try { existing = lstatSync(clonePath); } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    if (existing) {
      const stat = existing;
      if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`workspace clone path is not a real directory: ${clonePath}`);
      const probe = await requireCommandSuccess(
        this.runner,
        'git',
        ['-C', clonePath, 'rev-parse', '--is-inside-work-tree'],
        { timeoutMs: GIT_TIMEOUT_MS },
      );
      if (probe.stdout.trim() !== 'true') fail(`workspace clone is not a git worktree: ${clonePath}`);
      const origin = await requireCommandSuccess(
        this.runner,
        'git',
        ['-C', clonePath, 'remote', 'get-url', 'origin'],
        { timeoutMs: GIT_TIMEOUT_MS },
      );
      const originPath = origin.stdout.trim();
      if (originPath !== this.config.sourceRepo && resolve(originPath) !== this.config.sourceRepo) {
        fail(`existing workspace clone has an unexpected origin: ${clonePath}`);
      }
      const branch = await requireCommandSuccess(
        this.runner,
        'git',
        ['-C', clonePath, 'branch', '--show-current'],
        { timeoutMs: GIT_TIMEOUT_MS },
      );
      if (branch.stdout.trim() !== this.config.sourceBranch) {
        fail(`existing workspace clone is on ${JSON.stringify(branch.stdout.trim())}, expected ${this.config.sourceBranch}`);
      }
      chmodSync(clonePath, 0o700);
      this.prepareProjectLinks(clonePath);
      return;
    }
    // The parent is already private, and git creates the leaf itself. Do not
    // pre-create clonePath: that would turn a failed clone into an ambiguous
    // “existing workspace” that a later prepare might accidentally reuse.
    ensureDirectory(dirname(clonePath));
    await requireCommandSuccess(
      this.runner,
      'git',
      [
        'clone',
        '--no-hardlinks',
        '--single-branch',
        '--branch',
        this.config.sourceBranch,
        this.config.sourceRepo,
        clonePath,
      ],
      { timeoutMs: GIT_TIMEOUT_MS },
    );
    const stat = lstatSync(clonePath);
    if (!stat.isDirectory() || stat.isSymbolicLink()) fail(`git clone produced an unsafe workspace: ${clonePath}`);
    chmodSync(clonePath, 0o700);
    // A source branch may track placeholder/catalog files under qlib/data.
    // The fresh clone is disposable and those paths are replaced by the
    // approved read-only host mounts; an existing workspace is never altered.
    this.prepareProjectLinks(clonePath, { replaceFreshDirectories: true });
  }

  private prepareProjectLinks(
    clonePath: string,
    options: { readonly replaceFreshDirectories?: boolean } = {},
  ): void {
    const qlibRoot = join(clonePath, 'apps', 'quant-qlib');
    let qlibStat: ReturnType<typeof lstatSync>;
    try { qlibStat = lstatSync(qlibRoot); } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw error;
    }
    if (!qlibStat.isDirectory() || qlibStat.isSymbolicLink()) fail(`qlib project root is not a real directory: ${qlibRoot}`);
    const dataLink = join(qlibRoot, 'data');
    this.ensureProjectSymlink(
      dataLink,
      '/shared/quant-data',
      'qlib data',
      options.replaceFreshDirectories === true,
    );
    const knowledgeDir = join(qlibRoot, 'knowledge');
    if (!existsSync(knowledgeDir)) {
      ensureDirectory(knowledgeDir, 0o755);
    } else {
      const knowledgeStat = lstatSync(knowledgeDir);
      if (!knowledgeStat.isDirectory() || knowledgeStat.isSymbolicLink()) fail(`qlib knowledge root is not a real directory: ${knowledgeDir}`);
    }
    this.ensureProjectSymlink(
      join(knowledgeDir, 'investment-books'),
      '/knowledge/investment-books',
      'investment books',
      options.replaceFreshDirectories === true,
    );
  }

  private ensureProjectSymlink(
    path: string,
    target: string,
    label: string,
    replaceFreshDirectory: boolean,
  ): void {
    try {
      const stat = lstatSync(path);
      if (!stat.isSymbolicLink()) {
        if (replaceFreshDirectory && stat.isDirectory()) {
          rmSync(path, { recursive: true, force: true });
        } else {
          fail(`${label} exists but is not the required symlink: ${path}`);
        }
      }
      if (!lstatSync(path).isSymbolicLink()) fail(`${label} replacement did not produce a symlink slot: ${path}`);
      if (readlinkSync(path) !== target) fail(`${label} symlink target mismatch: ${path}`);
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
    symlinkSync(target, path);
  }

  launch(prepared: PreparedExecution, launch: PodmanCliLaunchSpec): ContainerLaunchSpec {
    assertPrepared(prepared, this.config);
    const cliArgs = checkCliLaunch(prepared, launch);
    if (prepared.credential.credentialKind === 'api'
      && (typeof launch.credentialSecret !== 'string' || launch.credentialSecret.length === 0)) {
      fail('API credential secret is required at launch time');
    }
    if (launch.credentialSecret !== undefined && typeof launch.credentialSecret !== 'string') {
      fail('credentialSecret must be a string');
    }
    if (prepared.credential.credentialKind !== 'api' && launch.credentialSecret !== undefined) {
      fail('credentialSecret is only valid for API credentials');
    }
    const credentialEnvironment = materializeCredentialEnvironment(
      prepared.credential,
      prepared.credential.credentialKind === 'api' ? launch.credentialSecret : undefined,
    );
    const runtimeEnvironment = validateRuntimeEnvironment(launch.runtimeEnv);
    const containerEnv: Record<string, string> = {
      HOME: CONTAINER_HOME,
      PATH: DEFAULT_PATH,
      SESSION_DATA_DIR: CONTAINER_SESSION_HOME,
      BOTMUX_HARNESS: cliHarness(prepared.cliId),
      BOTMUX_SESSION_ID: prepared.sessionId,
      BOTMUX_SESSION_HASH: prepared.runtime.sessionHash,
      BOTMUX_CREDENTIAL_KIND: prepared.credential.credentialKind,
      BOTMUX_CREDENTIAL_VERSION: String(prepared.credential.credentialVersion),
      AGENT_WORKSPACE: CONTAINER_WORKSPACE,
      AGENT_SESSION_HOME: CONTAINER_SESSION_HOME,
      AGENT_DATA_ROOT: CONTAINER_DATA_ROOT,
      AGENT_KNOWLEDGE_ROOT: CONTAINER_KNOWLEDGE_ROOT,
      AGENT_OUTBOX_ROOT: CONTAINER_OUTBOX_ROOT,
      // Data publish requests carry only a path relative to this per-session
      // staging root. The host relay derives the matching host path from the
      // same runtime workspace; no absolute host path crosses the boundary.
      BOTMUX_DATA_STAGING_ROOT: '/workspace/analyze/apps/quant-qlib/data/staging',
      BOTMUX_SEND_RELAY: CONTAINER_OUTBOX_ROOT,
      ...runtimeEnvironment,
      ...credentialEnvironment,
    };
    if (prepared.credential.providerConfig) {
      containerEnv.AGENT_BASE_URL = prepared.credential.providerConfig.baseUrl;
      containerEnv.AGENT_MODEL = prepared.credential.providerConfig.model;
    }
    if (prepared.credential.credentialKind === 'api') {
      // The T2 entrypoint consumes this generic triplet and aliases it to the
      // selected harness. Keep the legacy per-harness values too; they are
      // harmless and preserve compatibility with older image revisions.
      const secret = launch.credentialSecret!;
      containerEnv.AGENT_API_KEY = secret;
      if (prepared.credential.providerConfig) {
        containerEnv.AGENT_BASE_URL = prepared.credential.providerConfig.baseUrl;
        containerEnv.AGENT_MODEL = prepared.credential.providerConfig.model;
      }
    }
    if (prepared.credential.credentialKind === 'codex_chatgpt') {
      containerEnv.CODEX_HOME = join(CONTAINER_HOME, '.codex');
      containerEnv.CODEX_AUTH_FILE = join(CONTAINER_HOME, '.codex', 'auth.json');
    }
    const processEnv: Record<string, string> = { ...this.hostEnv };
    const secretKeys = new Set<string>();
    if (prepared.credential.credentialKind === 'api') {
      secretKeys.add('AGENT_API_KEY');
      if (prepared.credential.secretEnvVar) secretKeys.add(prepared.credential.secretEnvVar);
      processEnv.AGENT_API_KEY = launch.credentialSecret!;
      if (prepared.credential.secretEnvVar) processEnv[prepared.credential.secretEnvVar] = launch.credentialSecret!;
    }
    const args: string[] = [
      'run',
      '--rm',
      '--userns=keep-id',
      `--user=${prepared.hostUid}:${prepared.hostGid}`,
      `--network=${prepared.network.networkOption}`,
      ...prepared.network.addHosts.map(host => `--add-host=${host}`),
      '--cap-drop=ALL',
      '--security-opt=no-new-privileges',
      '--pids-limit=2048',
      `--memory=${prepared.config.memory}`,
      `--cpus=${String(prepared.config.cpus)}`,
      '--tmpfs=/tmp:rw,nosuid,nodev',
      '--label=io.botmux.managed=true',
      `--label=io.botmux.session=${prepared.runtime.sessionHash}`,
      `--name=${prepared.runtime.containerName}`,
      '--workdir=/workspace/analyze',
      ...prepared.mounts.map(mount => `--mount=${mountArgument(mount)}`),
    ];
    for (const [key, value] of Object.entries(containerEnv)) {
      // Secret-bearing values are read from the Podman client's explicit
      // process env. Every non-secret value is embedded as a fixed argv value
      // so setting container HOME never changes Podman's own host HOME.
      args.push(secretKeys.has(key) ? `--env=${key}` : `--env=${key}=${value}`);
    }
    args.push(prepared.config.image, '--', ...cliArgs);
    // The secret is intentionally absent from args. Callers must use env as
    // the child environment when spawning this exact Podman argv.
    return {
      bin: 'podman',
      args,
      cwd: prepared.hostWorkingDir,
      env: processEnv,
      containerName: prepared.runtime.containerName,
      cliId: prepared.cliId,
      runtime: prepared.runtime,
      transcriptPaths: prepared.transcriptPaths,
    };
  }

  async inspect(prepared: PreparedExecution): Promise<RuntimeState> {
    assertPrepared(prepared, this.config);
    const result = await runCommand(
      this.runner,
      'podman',
      ['container', 'inspect', '--format={{json .State}}', prepared.runtime.containerName],
      { timeoutMs: PODMAN_TIMEOUT_MS },
    );
    if (result.status !== 0) {
      if (/no such container|not found|does not exist/iu.test(result.stderr)) {
        return { status: 'missing', containerName: prepared.runtime.containerName };
      }
      return { status: 'unknown', containerName: prepared.runtime.containerName, error: result.stderr.trim() || `exit ${String(result.status)}` };
    }
    return parseInspectState(result.stdout.trim(), prepared.runtime.containerName);
  }

  async stop(prepared: PreparedExecution): Promise<void> {
    assertPrepared(prepared, this.config);
    const result = await runCommand(
      this.runner,
      'podman',
      ['stop', '--time', '10', prepared.runtime.containerName],
      { timeoutMs: PODMAN_TIMEOUT_MS },
    );
    if (result.status !== 0 && !/no such container|not found|does not exist/iu.test(result.stderr)) {
      fail(`could not stop ${prepared.runtime.containerName}: ${result.stderr.trim() || `exit ${String(result.status)}`}`);
    }
  }

  /**
   * Best-effort synchronous fallback for process-exit/crash paths. The normal
   * lifecycle awaits stop(); this hook exists because Node's `exit` event
   * cannot await a Promise and must still make a bounded stop attempt.
   */
  stopSyncBestEffort(prepared: PreparedExecution): void {
    try {
      assertPrepared(prepared, this.config);
      this.syncCommandRunner(
        'podman',
        ['stop', '--time', '10', prepared.runtime.containerName],
        { env: this.hostEnv, timeoutMs: PODMAN_TIMEOUT_MS },
      );
    } catch {
      // Exit/crash cleanup cannot report or recover from a failed stop.
    }
  }

  async destroyRuntime(prepared: PreparedExecution, authorization?: { readonly authorized: true }): Promise<void> {
    assertPrepared(prepared, this.config);
    if (!authorization || authorization.authorized !== true) {
      fail('destroyRuntime requires explicit authorized:true');
    }
    const runtimeRoot = resolve(this.config.runtimeRoot);
    const sessionRoot = resolve(prepared.runtime.sessionRoot);
    const rel = relative(runtimeRoot, sessionRoot);
    if (!rel || rel.startsWith('..') || resolve(runtimeRoot, rel) !== sessionRoot) {
      fail('refusing to destroy a runtime outside the configured runtimeRoot');
    }
    const sessionStat = lstatSync(sessionRoot);
    if (!sessionStat.isDirectory() || sessionStat.isSymbolicLink()) {
      fail('refusing to destroy a runtime that is not a real session directory');
    }
    const result = await runCommand(
      this.runner,
      'podman',
      ['rm', '--force', prepared.runtime.containerName],
      { timeoutMs: PODMAN_TIMEOUT_MS },
    );
    if (result.status !== 0 && !/no such container|not found|does not exist/iu.test(result.stderr)) {
      fail(`could not remove ${prepared.runtime.containerName}: ${result.stderr.trim() || `exit ${String(result.status)}`}`);
    }
    rmSync(sessionRoot, { recursive: true, force: true });
  }
}

function ensureProviderConfig(path: string, plan: NonNullable<CredentialInjectionPlan['providerConfig']>): void {
  const parsed = resolve(path);
  ensureDirectory(dirname(parsed));
  const body = plan.format === 'codex-toml'
    ? [
        'model_provider = "botmux_api"',
        `model = ${JSON.stringify(plan.model)}`,
        '',
        '[model_providers.botmux_api]',
        'name = "botmux_api"',
        `base_url = ${JSON.stringify(plan.baseUrl)}`,
        `env_key = ${JSON.stringify(plan.secretEnvVar)}`,
        'wire_api = "responses"',
        '',
      ].join('\n')
    : JSON.stringify({
        cliId: plan.cliId,
        credentialKind: plan.credentialKind,
        baseUrl: plan.baseUrl,
        model: plan.model,
      }, (_key, value) => value === undefined ? undefined : value) + '\n';
  // The provider config is a non-secret hint. Refuse a symlink and overwrite
  // only this provider-owned leaf, never an arbitrary file from a binding.
  if (existsSync(parsed)) {
    const stat = lstatSync(parsed);
    if (!stat.isFile() || stat.isSymbolicLink()) fail(`provider config is not a regular file: ${parsed}`);
  }
  writeFileSync(parsed, body, { mode: 0o600 });
  chmodSync(parsed, 0o600);
}

export const createPodmanExecutionProvider = (
  config: PodmanExecutionConfig,
  options?: PodmanExecutionProviderOptions,
): PodmanExecutionProvider => new PodmanExecutionProvider(config, options);

export {
  CONTAINER_DATA_ROOT,
  CONTAINER_HOME,
  CONTAINER_KNOWLEDGE_ROOT,
  CONTAINER_OUTBOX_ROOT,
  CONTAINER_SESSION_HOME,
  CONTAINER_WORKDIR,
  CONTAINER_WORKSPACE,
};
