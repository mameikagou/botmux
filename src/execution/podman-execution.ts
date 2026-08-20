/**
 * Pure planning and validation for the V3 shared-development Podman runtime.
 *
 * This module deliberately has no filesystem, database, Podman, or process
 * side effects.  T5 may consume these plans to create containers, but a bad
 * config or a bad principal must be rejected before any lifecycle operation is
 * attempted.
 */

import { createHash } from 'node:crypto';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';

export const PODMAN_EXECUTION_TYPE = 'podman' as const;
export const PODMAN_MEMORY_GATE_HOST = '127.0.0.1' as const;
export const PODMAN_MEMORY_GATE_PORT = 18181 as const;
export const PODMAN_RUNTIME_PRINCIPAL_HASH_LENGTH = 24 as const;
export const PODMAN_RUNTIME_SESSION_HASH_LENGTH = 24 as const;

const PODMAN_IMAGE_DIGEST_RE = /^[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}$/u;
const PODMAN_MEMORY_RE = /^[0-9]+(?:[kmgt]i?|[kmgt])?$/iu;
const PODMAN_BRANCH_RE = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/u;
const HASH_INPUT_RE = /[\u0000\r\n]/u;
const FORBIDDEN_HOST_PATHS = [
  '/home/admin',
  '/home',
  '/mnt/c',
  '/home/admin/mrlonely-code/brain',
  '/home/admin/mrlonely-code/agents/OpenMemory',
  '/home/admin/.codex',
  '/home/admin/.claude',
  '/home/admin/.ssh',
  '/home/admin/.aws',
  '/home/admin/.config/gh',
  '/home/admin/.git-credentials',
  '/run/user',
  '/var/run',
] as const;
const FORBIDDEN_EXACT_HOST_PATHS = new Set(['/home/admin', '/home', '/mnt/c']);

export const PODMAN_CLI_IDS = ['codex', 'claude-code', 'pi', 'opencode'] as const;
export type PodmanCliId = (typeof PODMAN_CLI_IDS)[number];

export const PODMAN_CREDENTIAL_KINDS = ['codex_chatgpt', 'api'] as const;
export type PodmanCredentialKind = (typeof PODMAN_CREDENTIAL_KINDS)[number];

/** The only execution fields accepted in a bot's `execution` object. */
export const PODMAN_EXECUTION_FIELDS = [
  'type',
  'image',
  'sourceRepo',
  'sourceBranch',
  'runtimeRoot',
  'credentialCacheRoot',
  'dataRoot',
  'knowledgeRoot',
  'ownerMemoryGate',
  'idleTimeoutMinutes',
  'memory',
  'cpus',
] as const;

export interface PodmanExecutionConfig {
  readonly type: typeof PODMAN_EXECUTION_TYPE;
  readonly image: string;
  readonly sourceRepo: string;
  readonly sourceBranch: string;
  readonly runtimeRoot: string;
  readonly credentialCacheRoot: string;
  readonly dataRoot: string;
  readonly knowledgeRoot: string;
  readonly ownerMemoryGate: `${typeof PODMAN_MEMORY_GATE_HOST}:${typeof PODMAN_MEMORY_GATE_PORT}`;
  readonly idleTimeoutMinutes: number;
  readonly memory: string;
  readonly cpus: number;
}

export type PrincipalKey =
  | { readonly larkAppId: string; readonly openId: string }
  | { readonly larkAppId: string; readonly open_id: string };

export interface SessionRuntimePaths {
  readonly principalHash: string;
  readonly sessionHash: string;
  readonly containerName: string;
  readonly principalRoot: string;
  readonly sessionRoot: string;
  readonly workspaceRoot: string;
  readonly homeRoot: string;
  readonly outboxRoot: string;
  /** Per-session writable qlib staging area. It is nested under the
   * read-only quant-data bind at container time, but never lives in the
   * central host dataRoot. */
  readonly stagingRoot: string;
  readonly runtimeStateRoot: string;
  readonly credentialCacheRoot: string;
  readonly codexCredentialRoot: string;
  readonly codexAuthPath: string;
}

export type PodmanMountMode = 'rw' | 'ro';

export interface PodmanMountPlan {
  readonly source: string;
  readonly target: string;
  readonly mode: PodmanMountMode;
  readonly kind: 'workspace' | 'home' | 'outbox' | 'quant-data' | 'quant-data-staging' | 'investment-books' | 'codex-auth';
  /** True only for the Codex auth.json leaf mount. */
  readonly singleFile?: true;
}

export interface PastaPortForward {
  readonly protocol: 'tcp';
  readonly hostAddress: typeof PODMAN_MEMORY_GATE_HOST;
  readonly hostPort: typeof PODMAN_MEMORY_GATE_PORT;
  readonly containerPort: typeof PODMAN_MEMORY_GATE_PORT;
  readonly purpose: 'memory-gate';
}

export interface PastaNetworkPlan {
  readonly network: 'pasta';
  readonly pastaArgs: readonly string[];
  readonly networkOption: string;
  readonly addHosts: readonly [
    'host.containers.internal:127.0.0.1',
    'host.docker.internal:127.0.0.1',
  ];
  readonly portForwards: readonly PastaPortForward[];
  readonly canOpenMemory: boolean;
}

export interface CredentialEnvironmentVariable {
  readonly name: string;
  readonly source: 'credential-kind' | 'credential-secret' | 'credential-base-url' | 'credential-model';
  readonly value?: string;
}

export interface CredentialProviderConfigPlan {
  readonly path: string;
  readonly format: 'json' | 'codex-toml';
  readonly cliId: PodmanCliId;
  readonly credentialKind: 'api';
  readonly baseUrl: string;
  readonly model: string;
  readonly secretEnvVar: string;
}

export interface CredentialInjectionPlan {
  readonly cliId: PodmanCliId;
  readonly credentialKind: PodmanCredentialKind;
  readonly credentialVersion: number;
  readonly environment: readonly CredentialEnvironmentVariable[];
  readonly secretEnvVar?: string;
  readonly providerConfig?: CredentialProviderConfigPlan;
  readonly codexAuthPath?: string;
}

export interface PodmanExecutionPlan {
  readonly cliId: PodmanCliId;
  readonly runtime: SessionRuntimePaths;
  readonly mounts: readonly PodmanMountPlan[];
  readonly network: PastaNetworkPlan;
  readonly credential: CredentialInjectionPlan;
}

function fail(path: string, message: string): never {
  throw new Error(`${path}: ${message}`);
}

function requireObject(raw: unknown, path: string): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) fail(path, 'must be an object');
  return raw as Record<string, unknown>;
}

function requireNonEmptyString(raw: unknown, path: string): string {
  if (typeof raw !== 'string' || !raw.trim()) fail(path, 'must be a non-empty string');
  if (HASH_INPUT_RE.test(raw)) fail(path, 'must not contain NUL or newline characters');
  return raw.trim();
}

function canonicalAbsolutePath(raw: unknown, path: string): string {
  const value = requireNonEmptyString(raw, path);
  // Backslashes are rejected even on POSIX.  They are a common source of
  // cross-platform path confusion when a config is copied from Windows.
  if (value.includes('\\')) fail(path, 'must use an absolute POSIX path');
  if (!isAbsolute(value)) fail(path, 'must be an absolute path');
  const segments = value.split('/');
  if (segments.includes('..')) fail(path, 'parent traversal is not allowed');
  const canonical = resolve(value);
  if (canonical === sep) fail(path, 'root path is not allowed');
  const lower = canonical.toLowerCase();
  const forbidden = FORBIDDEN_HOST_PATHS.find(candidate => {
    const candidateLower = candidate.toLowerCase();
    if (FORBIDDEN_EXACT_HOST_PATHS.has(candidate)) return lower === candidateLower;
    return lower === candidateLower || lower.startsWith(`${candidateLower}/`);
  });
  if (forbidden) fail(path, `path is inside a forbidden host root (${forbidden})`);
  // The shared-development profile must never point at the private knowledge
  // tree or OpenMemory under an alternate test root either.  Segment matching
  // avoids rejecting ordinary names such as /srv/brainstorm.
  const pathSegments = lower.split('/').filter(Boolean);
  if (pathSegments.includes('brain') || pathSegments.includes('openmemory')) {
    fail(path, 'brain/OpenMemory paths are not allowed');
  }
  return canonical;
}

function isSameOrDescendant(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

function pathsOverlap(a: string, b: string): boolean {
  return isSameOrDescendant(a, b) || isSameOrDescendant(b, a);
}

function validatePathLayout(config: {
  sourceRepo: string;
  runtimeRoot: string;
  credentialCacheRoot: string;
  dataRoot: string;
  knowledgeRoot: string;
}, path: string): void {
  const { sourceRepo, runtimeRoot, credentialCacheRoot, dataRoot, knowledgeRoot } = config;
  if (!isSameOrDescendant(sourceRepo, dataRoot) || sourceRepo === dataRoot) {
    fail(`${path}.dataRoot`, 'must be a strict descendant of sourceRepo');
  }
  if (!isSameOrDescendant(sourceRepo, knowledgeRoot) || sourceRepo === knowledgeRoot) {
    fail(`${path}.knowledgeRoot`, 'must be a strict descendant of sourceRepo');
  }
  if (pathsOverlap(dataRoot, knowledgeRoot)) {
    fail(path, 'dataRoot and knowledgeRoot must not overlap');
  }

  const independentRoots: Array<[string, string, string, string]> = [
    ['runtimeRoot', runtimeRoot, 'sourceRepo', sourceRepo],
    ['runtimeRoot', runtimeRoot, 'dataRoot', dataRoot],
    ['runtimeRoot', runtimeRoot, 'knowledgeRoot', knowledgeRoot],
    ['runtimeRoot', runtimeRoot, 'credentialCacheRoot', credentialCacheRoot],
    ['credentialCacheRoot', credentialCacheRoot, 'sourceRepo', sourceRepo],
    ['credentialCacheRoot', credentialCacheRoot, 'dataRoot', dataRoot],
    ['credentialCacheRoot', credentialCacheRoot, 'knowledgeRoot', knowledgeRoot],
  ];
  for (const [leftName, left, rightName, right] of independentRoots) {
    if (pathsOverlap(left, right)) {
      fail(path, `${leftName} and ${rightName} must not overlap`);
    }
  }
}

function parseBranch(raw: unknown, path: string): string {
  const branch = requireNonEmptyString(raw, path);
  if (!PODMAN_BRANCH_RE.test(branch) || branch.includes('..') || branch.includes('@{')
      || branch.endsWith('/') || branch.endsWith('.')) {
    fail(path, 'must be a safe git branch name');
  }
  return branch;
}

function parseImage(raw: unknown, path: string): string {
  const image = requireNonEmptyString(raw, path);
  if (!PODMAN_IMAGE_DIGEST_RE.test(image)) {
    fail(path, 'must include a lowercase sha256 digest (name@sha256:<64 hex>)');
  }
  return image;
}

function parseMemory(raw: unknown, path: string): string {
  const memory = requireNonEmptyString(raw, path).toLowerCase();
  if (!PODMAN_MEMORY_RE.test(memory)) fail(path, 'must be a positive Podman memory quantity');
  const amount = Number.parseInt(memory, 10);
  if (!Number.isSafeInteger(amount) || amount <= 0) fail(path, 'must be positive');
  return memory;
}

function parsePositiveFiniteNumber(raw: unknown, path: string): number {
  if (typeof raw !== 'number' || !Number.isFinite(raw) || raw <= 0) {
    fail(path, 'must be a positive finite number');
  }
  return raw;
}

function parsePositiveInteger(raw: unknown, path: string): number {
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw <= 0) {
    fail(path, 'must be a positive integer');
  }
  return raw;
}

/** Parse and strictly validate one `execution` config object. */
export function parsePodmanExecutionConfig(
  raw: unknown,
  path = 'execution',
): PodmanExecutionConfig {
  const entry = requireObject(raw, path);
  const unknownKeys = Object.keys(entry).filter(key => !(PODMAN_EXECUTION_FIELDS as readonly string[]).includes(key));
  if (unknownKeys.length > 0) fail(path, `unknown field(s): ${unknownKeys.join(', ')}`);

  if (entry.type !== PODMAN_EXECUTION_TYPE) fail(`${path}.type`, 'must be "podman"');
  const sourceRepo = canonicalAbsolutePath(entry.sourceRepo, `${path}.sourceRepo`);
  const runtimeRoot = canonicalAbsolutePath(entry.runtimeRoot, `${path}.runtimeRoot`);
  const credentialCacheRoot = canonicalAbsolutePath(entry.credentialCacheRoot, `${path}.credentialCacheRoot`);
  const dataRoot = canonicalAbsolutePath(entry.dataRoot, `${path}.dataRoot`);
  const knowledgeRoot = canonicalAbsolutePath(entry.knowledgeRoot, `${path}.knowledgeRoot`);
  validatePathLayout({ sourceRepo, runtimeRoot, credentialCacheRoot, dataRoot, knowledgeRoot }, path);

  const ownerMemoryGate = requireNonEmptyString(entry.ownerMemoryGate, `${path}.ownerMemoryGate`);
  if (ownerMemoryGate !== `${PODMAN_MEMORY_GATE_HOST}:${PODMAN_MEMORY_GATE_PORT}`) {
    fail(`${path}.ownerMemoryGate`, 'must be 127.0.0.1:18181');
  }

  return {
    type: PODMAN_EXECUTION_TYPE,
    image: parseImage(entry.image, `${path}.image`),
    sourceRepo,
    sourceBranch: parseBranch(entry.sourceBranch, `${path}.sourceBranch`),
    runtimeRoot,
    credentialCacheRoot,
    dataRoot,
    knowledgeRoot,
    ownerMemoryGate: ownerMemoryGate as PodmanExecutionConfig['ownerMemoryGate'],
    idleTimeoutMinutes: parsePositiveInteger(entry.idleTimeoutMinutes, `${path}.idleTimeoutMinutes`),
    memory: parseMemory(entry.memory, `${path}.memory`),
    cpus: parsePositiveFiniteNumber(entry.cpus, `${path}.cpus`),
  };
}

/** Alias used by config writers and callers that prefer “validate” terminology. */
export const validatePodmanExecutionConfig = parsePodmanExecutionConfig;
/** Alias used by older config normalizers. */
export const normalizePodmanExecutionConfig = parsePodmanExecutionConfig;

function safeHashPart(value: unknown, path: string): string {
  return requireNonEmptyString(value, path);
}

function principalOpenId(key: PrincipalKey): string {
  return 'openId' in key ? key.openId : key.open_id;
}

function digestPrefix(input: string, length: number): string {
  return createHash('sha256').update(input, 'utf8').digest('hex').slice(0, length);
}

/** SHA-256 prefix for the app-scoped principal; the raw open_id never appears in it. */
export function principalHash(key: PrincipalKey): string;
export function principalHash(larkAppId: string, openId: string): string;
export function principalHash(keyOrAppId: PrincipalKey | string, maybeOpenId?: string): string {
  const larkAppId = typeof keyOrAppId === 'string' ? keyOrAppId : keyOrAppId.larkAppId;
  const openId = typeof keyOrAppId === 'string' ? maybeOpenId : principalOpenId(keyOrAppId);
  return digestPrefix(
    `${safeHashPart(larkAppId, 'larkAppId')}:${safeHashPart(openId, 'openId')}`,
    PODMAN_RUNTIME_PRINCIPAL_HASH_LENGTH,
  );
}

/** SHA-256 prefix for one principal's botmux session; no plaintext identity is used in paths. */
export function sessionHash(key: PrincipalKey, sessionId: string): string;
export function sessionHash(larkAppId: string, openId: string, sessionId: string): string;
export function sessionHash(
  keyOrAppId: PrincipalKey | string,
  openIdOrSessionId: string,
  maybeSessionId?: string,
): string {
  const larkAppId = typeof keyOrAppId === 'string' ? keyOrAppId : keyOrAppId.larkAppId;
  const openId = typeof keyOrAppId === 'string' ? openIdOrSessionId : principalOpenId(keyOrAppId);
  const sessionId = typeof keyOrAppId === 'string' ? maybeSessionId : openIdOrSessionId;
  return digestPrefix(
    `${safeHashPart(larkAppId, 'larkAppId')}:${safeHashPart(openId, 'openId')}:${safeHashPart(sessionId, 'sessionId')}`,
    PODMAN_RUNTIME_SESSION_HASH_LENGTH,
  );
}

export const hashPrincipal = principalHash;
export const hashSession = sessionHash;

export function podmanContainerName(sessionHashValue: string): string {
  if (!/^[0-9a-f]{24}$/u.test(sessionHashValue)) {
    fail('sessionHash', 'must be a 24-character lowercase hash');
  }
  return `botmux-${sessionHashValue}`;
}

/** Build all host paths used by one isolated principal/session. */
export function buildSessionRuntimePaths(
  config: PodmanExecutionConfig,
  principal: PrincipalKey,
  sessionId: string,
): SessionRuntimePaths {
  const validatedConfig = parsePodmanExecutionConfig(config, 'config');
  const pHash = principalHash(principal);
  const sHash = sessionHash(principal, sessionId);
  const principalRoot = join(validatedConfig.runtimeRoot, pHash);
  const sessionRoot = join(principalRoot, sHash);
  const credentialCacheRoot = join(validatedConfig.credentialCacheRoot, pHash);
  const codexCredentialRoot = join(credentialCacheRoot, 'codex');
  return {
    principalHash: pHash,
    sessionHash: sHash,
    containerName: podmanContainerName(sHash),
    principalRoot,
    sessionRoot,
    workspaceRoot: join(sessionRoot, 'workspace'),
    homeRoot: join(sessionRoot, 'home'),
    outboxRoot: join(sessionRoot, 'outbox'),
    stagingRoot: join(sessionRoot, 'staging'),
    runtimeStateRoot: join(sessionRoot, 'runtime'),
    credentialCacheRoot,
    codexCredentialRoot,
    codexAuthPath: join(codexCredentialRoot, 'auth.json'),
  };
}

export const buildRuntimePathPlan = buildSessionRuntimePaths;
export const sessionRuntimePath = (
  config: PodmanExecutionConfig,
  principal: PrincipalKey,
  sessionId: string,
): string => buildSessionRuntimePaths(config, principal, sessionId).sessionRoot;
export const codexCredentialCachePath = (
  config: PodmanExecutionConfig,
  principal: PrincipalKey,
): string => buildSessionRuntimePaths(config, principal, '__credential_path__').codexAuthPath;

function asPodmanCliId(raw: unknown, path = 'cliId'): PodmanCliId {
  if (typeof raw !== 'string' || !(PODMAN_CLI_IDS as readonly string[]).includes(raw)) {
    fail(path, `must be one of ${PODMAN_CLI_IDS.join(', ')}`);
  }
  return raw as PodmanCliId;
}

function asCredentialKind(raw: unknown, path = 'credentialKind'): PodmanCredentialKind {
  if (typeof raw !== 'string' || !(PODMAN_CREDENTIAL_KINDS as readonly string[]).includes(raw)) {
    fail(path, 'must be codex_chatgpt or api');
  }
  return raw as PodmanCredentialKind;
}

/** A bot's harness is always its existing top-level `config.cliId`. */
export function fixedBotCliId(botConfig: { readonly cliId: string }): PodmanCliId {
  return asPodmanCliId(botConfig.cliId, 'bot.config.cliId');
}

export function isCredentialCompatible(cliId: string, credentialKind: string): boolean {
  if (!(PODMAN_CLI_IDS as readonly string[]).includes(cliId)) return false;
  if (!(PODMAN_CREDENTIAL_KINDS as readonly string[]).includes(credentialKind)) return false;
  return credentialKind === 'api' || cliId === 'codex';
}

export function assertCredentialCompatible(cliId: string, credentialKind: string): void {
  if (!isCredentialCompatible(cliId, credentialKind)) {
    fail('credential', `${credentialKind} is not compatible with bot cliId ${cliId}`);
  }
}

function credentialContract(cliId: PodmanCliId): {
  secretEnvVar: string;
  baseUrlEnvVar: string;
  modelEnvVar: string;
  configRelativePath: string;
} {
  switch (cliId) {
    case 'codex':
      return {
        secretEnvVar: 'OPENAI_API_KEY',
        baseUrlEnvVar: 'OPENAI_BASE_URL',
        modelEnvVar: 'OPENAI_MODEL',
        // Codex reads provider selection from CODEX_HOME/config.toml.  The
        // generic .agent/providers JSON is not part of Codex's schema.
        configRelativePath: '.codex/config.toml',
      };
    case 'claude-code':
      return {
        // Claude treats ANTHROPIC_API_KEY as an interactive custom-key
        // acknowledgement path.  The sandbox contract uses the bearer-token
        // variable so API credentials never trigger that login prompt.
        secretEnvVar: 'ANTHROPIC_AUTH_TOKEN',
        baseUrlEnvVar: 'ANTHROPIC_BASE_URL',
        modelEnvVar: 'ANTHROPIC_MODEL',
        configRelativePath: '.agent/providers/claude.json',
      };
    case 'pi':
      return {
        secretEnvVar: 'BOTMUX_API_KEY',
        baseUrlEnvVar: 'BOTMUX_BASE_URL',
        modelEnvVar: 'BOTMUX_MODEL',
        configRelativePath: '.agent/providers/pi.json',
      };
    case 'opencode':
      return {
        secretEnvVar: 'BOTMUX_API_KEY',
        baseUrlEnvVar: 'BOTMUX_BASE_URL',
        modelEnvVar: 'BOTMUX_MODEL',
        configRelativePath: '.agent/providers/opencode.json',
      };
  }
}

function validateCredentialBaseUrl(raw: unknown, path: string): string {
  const value = requireNonEmptyString(raw, path);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    fail(path, 'must be a valid HTTPS URL');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search) {
    fail(path, 'must be HTTPS without userinfo, query, or fragment');
  }
  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/gu, '');
  const isPrivate172 = /^172\.(?:1[6-9]|2[0-9]|3[0-1])\./u.test(hostname);
  if (
    hostname === 'localhost'
    || hostname.endsWith('.localhost')
    || hostname === '::1'
    || hostname === '127.0.0.1'
    || hostname === '0.0.0.0'
    || hostname.startsWith('10.')
    || isPrivate172
    || hostname.startsWith('192.168.')
    || hostname.startsWith('169.254.')
    || hostname.startsWith('100.64.')
    || hostname.startsWith('fc')
    || hostname.startsWith('fd')
    || hostname.startsWith('fe80:')
    || hostname.endsWith('.local')
  ) {
    fail(path, 'must not target localhost or a private/link-local host');
  }
  return value;
}

function validateCredentialVersion(raw: unknown, path: string): number {
  return parsePositiveInteger(raw, path);
}

function validateSessionHome(raw: unknown, path: string): string {
  return canonicalAbsolutePath(raw, path);
}

/**
 * Build a non-secret credential injection description.  API secrets are
 * represented by an env-var name only; callers that are about to spawn may
 * call materializeCredentialEnvironment(plan, secret) in memory.
 */
export function buildCredentialInjectionPlan(input: {
  readonly cliId: string;
  readonly credentialKind: string;
  readonly credentialVersion: number;
  readonly sessionHome: string;
  readonly authPath?: string;
  readonly baseUrl?: string;
  readonly model?: string;
}): CredentialInjectionPlan {
  const cliId = asPodmanCliId(input.cliId);
  const credentialKind = asCredentialKind(input.credentialKind);
  assertCredentialCompatible(cliId, credentialKind);
  const credentialVersion = validateCredentialVersion(input.credentialVersion, 'credentialVersion');
  const sessionHome = validateSessionHome(input.sessionHome, 'sessionHome');

  if (credentialKind === 'codex_chatgpt') {
    const authPath = canonicalAbsolutePath(input.authPath, 'authPath');
    if (!authPath.endsWith('/auth.json')) fail('authPath', 'must point to auth.json');
    return {
      cliId,
      credentialKind,
      credentialVersion,
      environment: [
        { name: 'BOTMUX_CREDENTIAL_KIND', source: 'credential-kind', value: credentialKind },
        { name: 'BOTMUX_CREDENTIAL_VERSION', source: 'credential-model', value: String(credentialVersion) },
      ],
      codexAuthPath: authPath,
    };
  }

  const baseUrl = validateCredentialBaseUrl(input.baseUrl, 'baseUrl');
  const model = requireNonEmptyString(input.model, 'model');
  const contract = credentialContract(cliId);
  const providerConfigPath = join(sessionHome, contract.configRelativePath);
  return {
    cliId,
    credentialKind,
    credentialVersion,
    environment: [
      { name: 'BOTMUX_CREDENTIAL_KIND', source: 'credential-kind', value: credentialKind },
      { name: 'BOTMUX_CREDENTIAL_VERSION', source: 'credential-model', value: String(credentialVersion) },
      { name: contract.baseUrlEnvVar, source: 'credential-base-url', value: baseUrl },
      { name: contract.modelEnvVar, source: 'credential-model', value: model },
    ],
    secretEnvVar: contract.secretEnvVar,
    providerConfig: {
      path: providerConfigPath,
      format: cliId === 'codex' ? 'codex-toml' : 'json',
      cliId,
      credentialKind: 'api',
      baseUrl,
      model,
      secretEnvVar: contract.secretEnvVar,
    },
  };
}

/** Materialize only at process launch; never persist or log the returned object. */
export function materializeCredentialEnvironment(
  plan: CredentialInjectionPlan,
  secret?: string,
): Record<string, string> {
  const environment: Record<string, string> = {};
  for (const variable of plan.environment) {
    if (variable.value !== undefined) environment[variable.name] = variable.value;
  }
  if (plan.secretEnvVar !== undefined) {
    if (typeof secret !== 'string' || !secret) fail('secret', 'must be provided for API credentials');
    environment[plan.secretEnvVar] = secret;
  }
  return environment;
}

function validateMountSource(source: string, kind: string): void {
  if (!isAbsolute(source) || source.includes('\\') || source.includes('\u0000')) {
    fail(`mount.${kind}`, 'source must be an absolute POSIX path');
  }
}

function assertRuntimePaths(config: PodmanExecutionConfig, runtime: SessionRuntimePaths): void {
  if (!/^[0-9a-f]{24}$/u.test(runtime.principalHash)) fail('runtime.principalHash', 'must be a 24-character lowercase hash');
  if (!/^[0-9a-f]{24}$/u.test(runtime.sessionHash)) fail('runtime.sessionHash', 'must be a 24-character lowercase hash');
  const expectedPrincipalRoot = join(config.runtimeRoot, runtime.principalHash);
  const expectedSessionRoot = join(expectedPrincipalRoot, runtime.sessionHash);
  const expectedCredentialRoot = join(config.credentialCacheRoot, runtime.principalHash);
  const expected = {
    containerName: podmanContainerName(runtime.sessionHash),
    principalRoot: expectedPrincipalRoot,
    sessionRoot: expectedSessionRoot,
    workspaceRoot: join(expectedSessionRoot, 'workspace'),
    homeRoot: join(expectedSessionRoot, 'home'),
    outboxRoot: join(expectedSessionRoot, 'outbox'),
    stagingRoot: join(expectedSessionRoot, 'staging'),
    runtimeStateRoot: join(expectedSessionRoot, 'runtime'),
    credentialCacheRoot: expectedCredentialRoot,
    codexCredentialRoot: join(expectedCredentialRoot, 'codex'),
    codexAuthPath: join(expectedCredentialRoot, 'codex', 'auth.json'),
  } as const;
  for (const key of Object.keys(expected) as Array<keyof typeof expected>) {
    if (runtime[key] !== expected[key]) fail(`runtime.${key}`, 'does not match the canonical session path plan');
  }
}

/** Build the exact V3 allow-listed bind mounts. */
export function buildPodmanMountPlan(
  config: PodmanExecutionConfig,
  runtime: SessionRuntimePaths,
  credential: Pick<CredentialInjectionPlan, 'credentialKind' | 'codexAuthPath'>
    & Partial<Pick<CredentialInjectionPlan, 'cliId'>>,
): readonly PodmanMountPlan[] {
  // Re-validate even when callers hold a TypeScript value.  T5 receives some
  // data from a database/config boundary, and a forged runtime object must not
  // turn this pure allow-list into an arbitrary bind-mount API.
  const validatedConfig = parsePodmanExecutionConfig(config, 'config');
  assertRuntimePaths(validatedConfig, runtime);
  const credentialKind = asCredentialKind(credential.credentialKind, 'credential.credentialKind');
  const base: PodmanMountPlan[] = [
    { source: runtime.workspaceRoot, target: '/workspace', mode: 'rw', kind: 'workspace' },
    { source: runtime.homeRoot, target: '/home/dev', mode: 'rw', kind: 'home' },
    { source: runtime.outboxRoot, target: '/session/outbox', mode: 'rw', kind: 'outbox' },
    { source: validatedConfig.dataRoot, target: '/shared/quant-data', mode: 'ro', kind: 'quant-data' },
    // qlib's data directory is a symlink to the read-only central lake. This
    // nested bind is the sole writable exception and is private per session;
    // it must appear after the parent bind so Podman overlays this leaf.
    { source: runtime.stagingRoot, target: '/shared/quant-data/staging', mode: 'rw', kind: 'quant-data-staging' },
    { source: validatedConfig.knowledgeRoot, target: '/knowledge/investment-books', mode: 'ro', kind: 'investment-books' },
  ];
  for (const mount of base) validateMountSource(mount.source, mount.kind);
  if (credentialKind === 'codex_chatgpt') {
    if (credential.cliId !== undefined && credential.cliId !== 'codex') {
      fail('credential.cliId', 'codex_chatgpt is only valid for codex');
    }
    const source = credential.codexAuthPath;
    if (!source) fail('credential.codexAuthPath', 'is required for codex_chatgpt');
    if (source !== runtime.codexAuthPath) fail('credential.codexAuthPath', 'must be the current principal auth.json path');
    validateMountSource(source, 'codex-auth');
    base.push({
      source,
      target: '/home/dev/.codex/auth.json',
      mode: 'rw',
      kind: 'codex-auth',
      singleFile: true,
    });
  }
  // The fixed targets and config layout make a custom/escaping mount
  // impossible.  Keep this assertion close to the plan so future additions
  // cannot accidentally broaden the allow list.
  const targets = new Set(base.map(mount => mount.target));
  if (targets.size !== base.length) fail('mounts', 'duplicate container target');
  return base;
}

export const buildMountPlan = buildPodmanMountPlan;

function networkInputCanOpenMemory(input: boolean | { readonly canOpenMemory?: boolean; readonly can_openmemory?: boolean }): boolean {
  if (typeof input === 'boolean') return input;
  if (!input || typeof input !== 'object') fail('canOpenMemory', 'must be a boolean');
  const camel = input.canOpenMemory;
  const snake = input.can_openmemory;
  if (camel !== undefined && typeof camel !== 'boolean') fail('canOpenMemory', 'must be a boolean');
  if (snake !== undefined && typeof snake !== 'boolean') fail('can_openmemory', 'must be a boolean');
  if (camel !== undefined && snake !== undefined && camel !== snake) fail('canOpenMemory', 'conflicting values');
  if (camel === undefined && snake === undefined) fail('canOpenMemory', 'must be provided');
  return camel ?? snake!;
}

/**
 * Generate the only supported rootless network profiles.  Host aliases are
 * deliberately pinned to the container loopback; the owner exception is a
 * single TCP 18181 pasta forward and never the raw OpenMemory 8181 port.
 */
export function buildPastaNetworkPlan(
  input: boolean | { readonly canOpenMemory?: boolean; readonly can_openmemory?: boolean },
): PastaNetworkPlan {
  const canOpenMemory = networkInputCanOpenMemory(input);
  const pastaArgs = canOpenMemory
    ? [
        '--no-map-gw',
        '-T',
        '18181',
      ]
    : ['--no-map-gw'];
  const networkOption = `pasta:${pastaArgs.join(',')}`;
  const portForwards: readonly PastaPortForward[] = canOpenMemory
    ? [{
        protocol: 'tcp',
        hostAddress: PODMAN_MEMORY_GATE_HOST,
        hostPort: PODMAN_MEMORY_GATE_PORT,
        containerPort: PODMAN_MEMORY_GATE_PORT,
        purpose: 'memory-gate',
      }]
    : [];
  return {
    network: 'pasta',
    pastaArgs,
    networkOption,
    addHosts: ['host.containers.internal:127.0.0.1', 'host.docker.internal:127.0.0.1'],
    portForwards,
    canOpenMemory,
  };
}

export const buildNetworkPlan = buildPastaNetworkPlan;

/** Combine all pure plans needed by the eventual T5 lifecycle provider. */
export function buildPodmanExecutionPlan(input: {
  readonly config: PodmanExecutionConfig;
  readonly botConfig: { readonly cliId: string };
  readonly principal: PrincipalKey;
  readonly sessionId: string;
  readonly canOpenMemory: boolean;
  readonly credential: {
    readonly kind: string;
    readonly version: number;
    readonly baseUrl?: string;
    readonly model?: string;
  };
}): PodmanExecutionPlan {
  const cliId = fixedBotCliId(input.botConfig);
  const runtime = buildSessionRuntimePaths(input.config, input.principal, input.sessionId);
  const injection = buildCredentialInjectionPlan({
    cliId,
    credentialKind: input.credential.kind,
    credentialVersion: input.credential.version,
    sessionHome: runtime.homeRoot,
    authPath: runtime.codexAuthPath,
    baseUrl: input.credential.baseUrl,
    model: input.credential.model,
  });
  const mounts = buildPodmanMountPlan(input.config, runtime, injection);
  return {
    cliId,
    runtime,
    mounts,
    network: buildPastaNetworkPlan(input.canOpenMemory),
    credential: injection,
  };
}
