/**
 * V4 sandbox user registry.
 *
 * V3 addressed a principal as `(lark_app_id, open_id)`. That is useful at
 * ingress, but it is not a durable owner identity: the same person may use
 * more than one app and a Pod must survive a worker restart. V4 introduces a
 * stable `sandbox_user_id`, maps app-scoped identities to it, keeps one
 * encrypted credential per harness, and retains a non-secret runtime
 * manifest after a Pod is stopped so a later cold start has an authoritative
 * record to resume from.
 *
 * This module owns only schema/repository state. It deliberately does not
 * start, stop, or inspect Podman containers.
 */
import { randomUUID } from 'node:crypto';
import {
  decryptCredentialUtf8,
  decryptSandboxUserCredentialUtf8,
  encryptSandboxUserCredential,
  credentialFingerprint,
} from './agent-principal-crypto.js';
import {
  AgentPrincipalLookupError,
  CredentialVersionConflictError,
  type AgentPrincipalKey,
  type AgentExecutionMode,
  type SqlExecutor,
  type SqlPool,
  type SqlTransaction,
} from './agent-principal-store.js';
import { validateApiCredentialInput } from './agent-credential-policy.js';
import {
  assertCredentialCompatible,
  type PodmanCliId,
  type PodmanCredentialKind,
} from '../execution/podman-execution.js';

export const SANDBOX_USER_REGISTRY_MIGRATION_ID = '20260820_sandbox_user_registry_v4';

export const SANDBOX_USER_HARNESSES = ['codex', 'claude-code', 'pi', 'opencode'] as const;
export type SandboxUserHarness = (typeof SANDBOX_USER_HARNESSES)[number];

export const SANDBOX_RUNTIME_STATES = ['provisioning', 'running', 'stopping', 'stopped', 'failed'] as const;
export type SandboxRuntimeState = (typeof SANDBOX_RUNTIME_STATES)[number];

export interface SandboxUserKey {
  readonly sandboxUserId: string;
}

export interface SandboxUserRow extends SandboxUserKey {
  readonly enabled: boolean;
  readonly canOpenMemory: boolean;
  readonly executionMode: AgentExecutionMode;
  /** Monotonic pod generation. Sessions freeze this value at ingress. */
  readonly podGeneration: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface SandboxUserIdentityRow extends AgentPrincipalKey, SandboxUserKey {
  readonly enabled: boolean;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface SandboxUserCredentialMetadata extends SandboxUserKey {
  readonly harness: SandboxUserHarness;
  readonly credentialKind: PodmanCredentialKind;
  readonly baseUrl?: string;
  readonly model?: string;
  readonly credentialVersion: number;
  readonly updatedAt: string;
  readonly keyFingerprint?: string;
}

interface SandboxUserCredentialRecord extends SandboxUserCredentialMetadata {
  readonly encryptedSecret: Buffer;
  readonly secretNonce: Buffer;
}

export interface SandboxPodRuntimeManifest {
  readonly runtimeId: string;
  readonly sandboxUserId: string;
  readonly sessionId: string;
  /** Frozen pod generation; a replacement pod can never reuse an old runtime. */
  readonly podGeneration: number;
  readonly harness: SandboxUserHarness;
  readonly state: SandboxRuntimeState;
  readonly imageDigest: string;
  readonly containerName?: string;
  readonly workspacePath?: string;
  readonly homePath?: string;
  readonly credentialVersion?: number;
  readonly sourceRepo?: string;
  readonly sourceBranch?: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly stoppedAt?: string;
  readonly failureCode?: string;
}

export interface SandboxUserBindingResult {
  readonly user: SandboxUserRow;
  readonly identity: SandboxUserIdentityRow;
  /** True only when a v3 encrypted credential was copied and re-encrypted. */
  readonly migratedCredential: boolean;
}

export type SandboxUserLookupFailureCode =
  | 'not_found'
  | 'disabled'
  | 'identity_conflict'
  | 'credential_missing'
  | 'credential_incompatible'
  | 'runtime_conflict'
  | 'database_unavailable';

export class SandboxUserLookupError extends Error {
  readonly code: SandboxUserLookupFailureCode;
  constructor(code: SandboxUserLookupFailureCode, message: string = code) {
    super(message);
    this.name = 'SandboxUserLookupError';
    this.code = code;
  }
}

export class SandboxCredentialVersionConflictError extends CredentialVersionConflictError {
  constructor(expectedVersion: number, actualVersion?: number) {
    super(expectedVersion, actualVersion);
    this.name = 'SandboxCredentialVersionConflictError';
  }
}

export class SandboxRuntimeStateConflictError extends Error {
  readonly runtimeId: string;
  readonly expectedState: SandboxRuntimeState;
  readonly actualState?: SandboxRuntimeState;
  constructor(runtimeId: string, expectedState: SandboxRuntimeState, actualState?: SandboxRuntimeState) {
    super('sandbox_runtime_state_conflict');
    this.name = 'SandboxRuntimeStateConflictError';
    this.runtimeId = runtimeId;
    this.expectedState = expectedState;
    this.actualState = actualState;
  }
}

export class SandboxPodGenerationConflictError extends Error {
  readonly expectedGeneration: number;
  readonly actualGeneration?: number;
  constructor(expectedGeneration: number, actualGeneration?: number) {
    super('sandbox_pod_generation_conflict');
    this.name = 'SandboxPodGenerationConflictError';
    this.expectedGeneration = expectedGeneration;
    this.actualGeneration = actualGeneration;
  }
}

/** New tables are additive; v3 agent_principals remains the compatibility source. */
export const SANDBOX_USER_REGISTRY_UP_SQL = `
CREATE TABLE IF NOT EXISTS sandbox_users (
  sandbox_user_id text PRIMARY KEY,
  enabled boolean NOT NULL DEFAULT true,
  can_openmemory boolean NOT NULL DEFAULT false,
  execution_mode text NOT NULL DEFAULT 'podman'
    CHECK (execution_mode IN ('native', 'podman')),
  pod_generation bigint NOT NULL DEFAULT 1 CHECK (pod_generation > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (length(trim(sandbox_user_id)) > 0)
);
ALTER TABLE sandbox_users
  ADD COLUMN IF NOT EXISTS pod_generation bigint NOT NULL DEFAULT 1;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'sandbox_users'::regclass
      AND conname = 'sandbox_users_pod_generation_check'
  ) THEN
    ALTER TABLE sandbox_users
      ADD CONSTRAINT sandbox_users_pod_generation_check
      CHECK (pod_generation > 0);
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS sandbox_user_identities (
  sandbox_user_id text NOT NULL REFERENCES sandbox_users (sandbox_user_id)
    ON UPDATE CASCADE ON DELETE CASCADE,
  lark_app_id text NOT NULL,
  open_id text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (lark_app_id, open_id),
  CHECK (length(trim(lark_app_id)) > 0),
  CHECK (length(trim(open_id)) > 0)
);
CREATE INDEX IF NOT EXISTS sandbox_user_identities_user_idx
  ON sandbox_user_identities (sandbox_user_id, enabled);

CREATE TABLE IF NOT EXISTS sandbox_user_credentials (
  sandbox_user_id text NOT NULL REFERENCES sandbox_users (sandbox_user_id)
    ON UPDATE CASCADE ON DELETE CASCADE,
  harness text NOT NULL CHECK (harness IN ('codex', 'claude-code', 'pi', 'opencode')),
  credential_kind text NOT NULL CHECK (credential_kind IN ('codex_chatgpt', 'api')),
  base_url text,
  model text,
  encrypted_secret bytea NOT NULL,
  secret_nonce bytea NOT NULL,
  credential_version bigint NOT NULL DEFAULT 1 CHECK (credential_version > 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (sandbox_user_id, harness),
  CHECK ((credential_kind = 'api' AND length(trim(coalesce(base_url, ''))) > 0
          AND length(trim(coalesce(model, ''))) > 0)
      OR (credential_kind = 'codex_chatgpt' AND base_url IS NULL AND model IS NULL))
);

CREATE TABLE IF NOT EXISTS sandbox_pod_runtime_manifests (
  runtime_id text PRIMARY KEY,
  sandbox_user_id text NOT NULL REFERENCES sandbox_users (sandbox_user_id)
    ON UPDATE CASCADE ON DELETE CASCADE,
  session_id text NOT NULL,
  pod_generation bigint NOT NULL DEFAULT 1 CHECK (pod_generation > 0),
  harness text NOT NULL CHECK (harness IN ('codex', 'claude-code', 'pi', 'opencode')),
  state text NOT NULL CHECK (state IN ('provisioning', 'running', 'stopping', 'stopped', 'failed')),
  image_digest text NOT NULL,
  container_name text,
  workspace_path text,
  home_path text,
  credential_version bigint CHECK (credential_version IS NULL OR credential_version > 0),
  source_repo text,
  source_branch text,
  manifest jsonb NOT NULL DEFAULT '{}'::jsonb,
  failure_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  stopped_at timestamptz,
  CONSTRAINT sandbox_pod_runtime_manifests_session_generation_key UNIQUE (session_id, pod_generation),
  CHECK (length(trim(runtime_id)) > 0),
  CHECK (length(trim(session_id)) > 0),
  CHECK (length(trim(image_digest)) > 0)
);
CREATE INDEX IF NOT EXISTS sandbox_pod_runtime_user_state_idx
  ON sandbox_pod_runtime_manifests (sandbox_user_id, state, updated_at DESC);
ALTER TABLE sandbox_pod_runtime_manifests
  ADD COLUMN IF NOT EXISTS pod_generation bigint NOT NULL DEFAULT 1;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'sandbox_pod_runtime_manifests'::regclass
      AND conname = 'sandbox_pod_runtime_manifests_pod_generation_check'
  ) THEN
    ALTER TABLE sandbox_pod_runtime_manifests
      ADD CONSTRAINT sandbox_pod_runtime_manifests_pod_generation_check
      CHECK (pod_generation > 0);
  END IF;
END $$;
ALTER TABLE sandbox_pod_runtime_manifests
  DROP CONSTRAINT IF EXISTS sandbox_pod_runtime_manifests_session_id_key;
CREATE UNIQUE INDEX IF NOT EXISTS sandbox_pod_runtime_manifests_session_generation_key
  ON sandbox_pod_runtime_manifests (session_id, pod_generation);
`;

export const SANDBOX_USER_REGISTRY_DOWN_SQL = `
DROP TABLE IF EXISTS sandbox_pod_runtime_manifests;
DROP TABLE IF EXISTS sandbox_user_credentials;
DROP TABLE IF EXISTS sandbox_user_identities;
DROP TABLE IF EXISTS sandbox_users;
`;

function textValue(raw: unknown, name: string): string {
  if (typeof raw !== 'string' || !raw.trim() || /[\u0000\r\n]/u.test(raw)) {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return raw.trim();
}

function sandboxUserIdValue(raw: unknown): string {
  const value = textValue(raw, 'sandboxUserId');
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value)) throw new TypeError('sandboxUserId contains unsafe characters');
  return value;
}

function harnessValue(raw: unknown): SandboxUserHarness {
  if (typeof raw !== 'string' || !(SANDBOX_USER_HARNESSES as readonly string[]).includes(raw)) {
    throw new TypeError('invalid sandbox harness');
  }
  return raw as SandboxUserHarness;
}

function stateValue(raw: unknown): SandboxRuntimeState {
  if (typeof raw !== 'string' || !(SANDBOX_RUNTIME_STATES as readonly string[]).includes(raw)) {
    throw new TypeError('invalid sandbox runtime state');
  }
  return raw as SandboxRuntimeState;
}

function dateValue(raw: unknown): string {
  return raw instanceof Date ? raw.toISOString() : typeof raw === 'string' ? raw : new Date(0).toISOString();
}

function boolValue(raw: unknown, fallback = false): boolean {
  return typeof raw === 'boolean' ? raw : raw === 't' ? true : raw === 'f' ? false : fallback;
}

function positiveGeneration(raw: unknown, name: string): number {
  const generation = Number(raw);
  if (!Number.isSafeInteger(generation) || generation < 1) {
    throw new TypeError(`${name} must be a positive integer`);
  }
  return generation;
}

function parseUser(row: Record<string, unknown>): SandboxUserRow {
  return {
    sandboxUserId: String(row.sandbox_user_id),
    enabled: boolValue(row.enabled),
    canOpenMemory: boolValue(row.can_openmemory),
    executionMode: row.execution_mode === 'native' ? 'native' : 'podman',
    podGeneration: positiveGeneration(row.pod_generation, 'sandbox user pod_generation'),
    createdAt: dateValue(row.created_at),
    updatedAt: dateValue(row.updated_at),
  };
}

function parseIdentity(row: Record<string, unknown>): SandboxUserIdentityRow {
  return {
    sandboxUserId: String(row.sandbox_user_id),
    larkAppId: String(row.lark_app_id),
    openId: String(row.open_id),
    enabled: boolValue(row.identity_enabled ?? row.enabled, true),
    createdAt: dateValue(row.identity_created_at ?? row.created_at),
    updatedAt: dateValue(row.identity_updated_at ?? row.updated_at),
  };
}

function bytes(value: unknown): Buffer {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === 'string') {
    const hex = value.startsWith('\\x') ? value.slice(2) : value;
    if (/^[0-9a-f]+$/iu.test(hex) && hex.length % 2 === 0) return Buffer.from(hex, 'hex');
    return Buffer.from(value, 'base64');
  }
  throw new TypeError('credential bytes are invalid');
}

function parseCredential(row: Record<string, unknown>): SandboxUserCredentialRecord {
  return {
    sandboxUserId: String(row.sandbox_user_id),
    harness: harnessValue(String(row.harness)),
    credentialKind: String(row.credential_kind) as PodmanCredentialKind,
    ...(typeof row.base_url === 'string' ? { baseUrl: row.base_url } : {}),
    ...(typeof row.model === 'string' ? { model: row.model } : {}),
    credentialVersion: Number(row.credential_version),
    updatedAt: dateValue(row.updated_at),
    encryptedSecret: bytes(row.encrypted_secret),
    secretNonce: bytes(row.secret_nonce),
  };
}

function parseRuntime(row: Record<string, unknown>): SandboxPodRuntimeManifest {
  return {
    runtimeId: String(row.runtime_id),
    sandboxUserId: String(row.sandbox_user_id),
    sessionId: String(row.session_id),
    podGeneration: positiveGeneration(row.pod_generation, 'sandbox runtime pod_generation'),
    harness: harnessValue(String(row.harness)),
    state: stateValue(row.state),
    imageDigest: String(row.image_digest),
    ...(typeof row.container_name === 'string' ? { containerName: row.container_name } : {}),
    ...(typeof row.workspace_path === 'string' ? { workspacePath: row.workspace_path } : {}),
    ...(typeof row.home_path === 'string' ? { homePath: row.home_path } : {}),
    ...(row.credential_version !== null && row.credential_version !== undefined ? { credentialVersion: Number(row.credential_version) } : {}),
    ...(typeof row.source_repo === 'string' ? { sourceRepo: row.source_repo } : {}),
    ...(typeof row.source_branch === 'string' ? { sourceBranch: row.source_branch } : {}),
    createdAt: dateValue(row.created_at),
    updatedAt: dateValue(row.updated_at),
    ...(row.stopped_at ? { stoppedAt: dateValue(row.stopped_at) } : {}),
    ...(typeof row.failure_code === 'string' ? { failureCode: row.failure_code } : {}),
  };
}

function isDomainError(error: unknown): boolean {
  return error instanceof SandboxUserLookupError
    || error instanceof SandboxCredentialVersionConflictError
    || error instanceof SandboxRuntimeStateConflictError
    || error instanceof CredentialVersionConflictError
    || error instanceof AgentPrincipalLookupError;
}

function dbError(error: unknown): SandboxUserLookupError {
  if (error instanceof SandboxUserLookupError) return error;
  if (error instanceof SandboxCredentialVersionConflictError) throw error;
  if (error instanceof SandboxRuntimeStateConflictError) throw error;
  return new SandboxUserLookupError('database_unavailable', 'sandbox user database unavailable');
}

async function withTransaction<T>(db: SqlPool, operation: (tx: SqlTransaction) => Promise<T>): Promise<T> {
  let client: SqlTransaction;
  try {
    client = await db.connect();
  } catch (error) {
    throw dbError(error);
  }
  try {
    await client.query('BEGIN');
    const result = await operation(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    if (isDomainError(error)) throw error;
    throw dbError(error);
  } finally {
    client.release();
  }
}

function keyValues(key: AgentPrincipalKey): [string, string] {
  return [textValue(key.larkAppId, 'larkAppId'), textValue(key.openId, 'openId')];
}

function ensureCredentialShape(input: {
  readonly harness: SandboxUserHarness;
  readonly credentialKind: PodmanCredentialKind;
  readonly secret: string | Buffer;
  readonly baseUrl?: string;
  readonly model?: string;
}): string {
  const secret = typeof input.secret === 'string' ? input.secret : input.secret.toString('utf8');
  if (!secret.trim()) throw new TypeError('credential secret must be non-empty');
  try { assertCredentialCompatible(input.harness as PodmanCliId, input.credentialKind); } catch {
    throw new SandboxUserLookupError('credential_incompatible', 'credential is incompatible with this harness');
  }
  if (input.credentialKind === 'api') {
    validateApiCredentialInput({ baseUrl: input.baseUrl ?? '', model: input.model ?? '', key: secret });
  } else if (input.baseUrl !== undefined || input.model !== undefined) {
    throw new TypeError('Codex ChatGPT credentials do not accept BaseURL or model');
  }
  return secret;
}

function safeRuntimeInput(input: {
  readonly runtimeId: string;
  readonly sessionId: string;
  readonly podGeneration: number;
  readonly imageDigest: string;
  readonly containerName?: string;
  readonly workspacePath?: string;
  readonly homePath?: string;
  readonly credentialVersion?: number;
  readonly sourceRepo?: string;
  readonly sourceBranch?: string;
}): void {
  for (const [name, value] of Object.entries(input)) {
    if (value !== undefined && typeof value === 'string') textValue(value, name);
  }
  if (input.credentialVersion !== undefined
    && (!Number.isSafeInteger(input.credentialVersion) || input.credentialVersion < 1)) {
    throw new TypeError('credentialVersion must be a positive integer');
  }
  if (!Number.isSafeInteger(input.podGeneration) || input.podGeneration < 1) {
    throw new TypeError('podGeneration must be a positive integer');
  }
}

export async function applySandboxUserRegistryMigration(db: SqlExecutor): Promise<void> {
  // Pool-backed callers should use the same connection for the whole DDL
  // batch. The tiny adapter fallback is kept for unit/test executors.
  const connect = (db as Partial<SqlPool>).connect;
  if (typeof connect !== 'function') {
    try { await db.query(SANDBOX_USER_REGISTRY_UP_SQL); } catch (error) { throw dbError(error); }
    return;
  }
  let client: SqlTransaction;
  try { client = await connect.call(db); } catch (error) { throw dbError(error); }
  try {
    await client.query('BEGIN');
    await client.query(`SELECT pg_advisory_xact_lock(hashtext('botmux:agent-principal-migrations'))`);
    await client.query(SANDBOX_USER_REGISTRY_UP_SQL);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw dbError(error);
  } finally {
    client.release();
  }
}

export async function rollbackSandboxUserRegistryMigration(db: SqlExecutor): Promise<void> {
  const connect = (db as Partial<SqlPool>).connect;
  if (typeof connect !== 'function') {
    try { await db.query(SANDBOX_USER_REGISTRY_DOWN_SQL); } catch (error) { throw dbError(error); }
    return;
  }
  let client: SqlTransaction;
  try { client = await connect.call(db); } catch (error) { throw dbError(error); }
  try {
    await client.query('BEGIN');
    await client.query(SANDBOX_USER_REGISTRY_DOWN_SQL);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw dbError(error);
  } finally {
    client.release();
  }
}

export class SandboxUserRegistryRepository {
  constructor(
    private readonly db: SqlPool,
    private readonly masterKey?: Buffer,
  ) {}

  async createUser(input: {
    readonly sandboxUserId?: string;
    readonly enabled?: boolean;
    readonly canOpenMemory?: boolean;
    readonly executionMode?: AgentExecutionMode;
  } = {}): Promise<SandboxUserRow> {
    const id = sandboxUserIdValue(input.sandboxUserId ?? randomUUID());
    const mode = input.executionMode ?? 'podman';
    if (mode !== 'native' && mode !== 'podman') throw new TypeError('invalid execution mode');
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `INSERT INTO sandbox_users (sandbox_user_id, enabled, can_openmemory, execution_mode)
         VALUES ($1, COALESCE($2, true), COALESCE($3, false), COALESCE($4, 'podman'))
         ON CONFLICT (sandbox_user_id) DO UPDATE SET
           enabled = COALESCE($2, sandbox_users.enabled),
           can_openmemory = COALESCE($3, sandbox_users.can_openmemory),
           execution_mode = COALESCE($4, sandbox_users.execution_mode),
           updated_at = now()
         RETURNING sandbox_user_id, enabled, can_openmemory, execution_mode, pod_generation, created_at, updated_at`,
        [id, input.enabled ?? null, input.canOpenMemory ?? null, input.executionMode ?? null],
      );
      return parseUser(result.rows[0]!);
    } catch (error) { throw dbError(error); }
  }

  async getUser(key: SandboxUserKey): Promise<SandboxUserRow | undefined> {
    const id = sandboxUserIdValue(key.sandboxUserId);
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `SELECT sandbox_user_id, enabled, can_openmemory, execution_mode, pod_generation, created_at, updated_at
           FROM sandbox_users WHERE sandbox_user_id = $1`, [id],
      );
      return result.rows[0] ? parseUser(result.rows[0]) : undefined;
    } catch (error) { throw dbError(error); }
  }

  async listUsers(): Promise<readonly SandboxUserRow[]> {
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `SELECT sandbox_user_id, enabled, can_openmemory, execution_mode, pod_generation, created_at, updated_at
           FROM sandbox_users
          ORDER BY created_at ASC, sandbox_user_id ASC`,
      );
      return result.rows.map(parseUser);
    } catch (error) { throw dbError(error); }
  }

  async listIdentities(user?: SandboxUserKey): Promise<readonly SandboxUserIdentityRow[]> {
    const userId = user ? sandboxUserIdValue(user.sandboxUserId) : undefined;
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `SELECT sandbox_user_id, lark_app_id, open_id, enabled AS identity_enabled,
                created_at AS identity_created_at, updated_at AS identity_updated_at
           FROM sandbox_user_identities
          WHERE ($1::text IS NULL OR sandbox_user_id = $1)
          ORDER BY sandbox_user_id ASC, lark_app_id ASC`,
        [userId ?? null],
      );
      return result.rows.map(parseIdentity);
    } catch (error) { throw dbError(error); }
  }

  /**
   * Enabling or disabling a user also advances its Pod generation. This makes
   * every already-frozen topic fail its next cold rebuild instead of reviving
   * an instance created under the previous authorization state.
   */
  async setUserEnabled(key: SandboxUserKey, enabled: boolean): Promise<SandboxUserRow> {
    const id = sandboxUserIdValue(key.sandboxUserId);
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `UPDATE sandbox_users
            SET enabled = $2,
                pod_generation = CASE WHEN enabled IS DISTINCT FROM $2 THEN pod_generation + 1 ELSE pod_generation END,
                updated_at = now()
          WHERE sandbox_user_id = $1
        RETURNING sandbox_user_id, enabled, can_openmemory, execution_mode, pod_generation, created_at, updated_at`,
        [id, enabled],
      );
      if (!result.rows[0]) throw new SandboxUserLookupError('not_found', 'sandbox user is not registered');
      return parseUser(result.rows[0]);
    } catch (error) {
      if (error instanceof SandboxUserLookupError) throw error;
      throw dbError(error);
    }
  }

  /**
   * Atomically fence a replacement pod. Existing sessions keep their frozen
   * generation and therefore cannot attach to the replacement. New sessions
   * read the returned generation at ingress.
   */
  async advancePodGeneration(key: SandboxUserKey, expectedGeneration?: number): Promise<SandboxUserRow> {
    const id = sandboxUserIdValue(key.sandboxUserId);
    if (expectedGeneration !== undefined && (!Number.isSafeInteger(expectedGeneration) || expectedGeneration < 1)) {
      throw new TypeError('expectedGeneration must be a positive integer');
    }
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `UPDATE sandbox_users
            SET pod_generation = pod_generation + 1, updated_at = now()
          WHERE sandbox_user_id = $1
            AND ($2::bigint IS NULL OR pod_generation = $2)
        RETURNING sandbox_user_id, enabled, can_openmemory, execution_mode, pod_generation, created_at, updated_at`,
        [id, expectedGeneration ?? null],
      );
      if (!result.rows[0]) {
        const current = await this.getUser({ sandboxUserId: id });
        if (!current) throw new SandboxUserLookupError('not_found', 'sandbox user is not registered');
        throw new SandboxPodGenerationConflictError(expectedGeneration!, current.podGeneration);
      }
      return parseUser(result.rows[0]);
    } catch (error) {
      if (error instanceof SandboxUserLookupError || error instanceof SandboxPodGenerationConflictError) throw error;
      throw dbError(error);
    }
  }

  async getIdentity(key: AgentPrincipalKey): Promise<SandboxUserIdentityRow | undefined> {
    const [appId, openId] = keyValues(key);
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `SELECT i.sandbox_user_id, i.lark_app_id, i.open_id, i.enabled AS identity_enabled,
                i.created_at AS identity_created_at, i.updated_at AS identity_updated_at
           FROM sandbox_user_identities i
          WHERE i.lark_app_id = $1 AND i.open_id = $2`, [appId, openId],
      );
      return result.rows[0] ? parseIdentity(result.rows[0]) : undefined;
    } catch (error) { throw dbError(error); }
  }

  /** Resolve the app-scoped ingress identity to its stable user, fail closed. */
  async resolveUserForIdentity(key: AgentPrincipalKey): Promise<{ user: SandboxUserRow; identity: SandboxUserIdentityRow }> {
    const [appId, openId] = keyValues(key);
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `SELECT u.sandbox_user_id, u.enabled, u.can_openmemory, u.execution_mode, u.pod_generation,
                u.created_at, u.updated_at,
                i.lark_app_id, i.open_id, i.enabled AS identity_enabled,
                i.created_at AS identity_created_at, i.updated_at AS identity_updated_at
           FROM sandbox_user_identities i
           JOIN sandbox_users u ON u.sandbox_user_id = i.sandbox_user_id
          WHERE i.lark_app_id = $1 AND i.open_id = $2`, [appId, openId],
      );
      const row = result.rows[0];
      if (!row) throw new SandboxUserLookupError('not_found', 'sandbox user identity is not registered');
      const identity = parseIdentity(row);
      const user = parseUser(row);
      if (!identity.enabled || !user.enabled) throw new SandboxUserLookupError('disabled', 'sandbox user identity is disabled');
      return { user, identity };
    } catch (error) {
      if (error instanceof SandboxUserLookupError) throw error;
      throw dbError(error);
    }
  }

  /** Bind one app-scoped identity to an existing or newly-created stable user. */
  async bindIdentity(input: {
    readonly key: AgentPrincipalKey;
    readonly sandboxUserId?: string;
    readonly enabled?: boolean;
  }): Promise<SandboxUserBindingResult> {
    const [appId, openId] = keyValues(input.key);
    return withTransaction(this.db, async tx => {
      const existing = await tx.query<Record<string, unknown>>(
        `SELECT sandbox_user_id FROM sandbox_user_identities WHERE lark_app_id = $1 AND open_id = $2 FOR UPDATE`,
        [appId, openId],
      );
      const userId = sandboxUserIdValue(input.sandboxUserId
        ?? (existing.rows[0] ? String(existing.rows[0].sandbox_user_id) : randomUUID()));
      if (existing.rows[0] && String(existing.rows[0].sandbox_user_id) !== userId) {
        throw new SandboxUserLookupError('identity_conflict', 'app-scoped identity is already bound to another sandbox user');
      }
      const user = await tx.query<Record<string, unknown>>(
        `INSERT INTO sandbox_users (sandbox_user_id) VALUES ($1)
         ON CONFLICT (sandbox_user_id) DO UPDATE SET updated_at = now()
         RETURNING sandbox_user_id, enabled, can_openmemory, execution_mode, pod_generation, created_at, updated_at`, [userId],
      );
      const identity = await tx.query<Record<string, unknown>>(
        `INSERT INTO sandbox_user_identities (sandbox_user_id, lark_app_id, open_id, enabled)
         VALUES ($1, $2, $3, COALESCE($4, true))
         ON CONFLICT (lark_app_id, open_id) DO UPDATE SET
           sandbox_user_id = EXCLUDED.sandbox_user_id,
           enabled = COALESCE($4, sandbox_user_identities.enabled),
           updated_at = now()
         RETURNING sandbox_user_id, lark_app_id, open_id, enabled,
                   created_at, updated_at`,
        [userId, appId, openId, input.enabled ?? null],
      );
      return {
        user: parseUser(user.rows[0]!),
        identity: parseIdentity(identity.rows[0]!),
        migratedCredential: false,
      };
    });
  }

  /**
   * Migrate a v3 principal and its optional credential into a stable user.
   * The old row remains intact for rolling downgrade. The new ciphertext is
   * authenticated with user+harness+metadata AAD, never the old app/open key.
   */
  async migrateLegacyPrincipal(input: {
    readonly key: AgentPrincipalKey;
    readonly harness: SandboxUserHarness;
    readonly sandboxUserId?: string;
  }): Promise<SandboxUserBindingResult> {
    const [appId, openId] = keyValues(input.key);
    const harness = harnessValue(input.harness);
    if (!this.masterKey) throw new SandboxUserLookupError('database_unavailable', 'credential master key is not configured');
    const masterKey = this.masterKey;
    return withTransaction(this.db, async tx => {
      const principal = await tx.query<Record<string, unknown>>(
        `SELECT lark_app_id, open_id, enabled, can_openmemory, execution_mode, created_at, updated_at
           FROM agent_principals WHERE lark_app_id = $1 AND open_id = $2 FOR UPDATE`, [appId, openId],
      );
      const source = principal.rows[0];
      if (!source) throw new SandboxUserLookupError('not_found', 'legacy agent principal is not registered');
      const existingIdentity = await tx.query<Record<string, unknown>>(
        `SELECT sandbox_user_id FROM sandbox_user_identities WHERE lark_app_id = $1 AND open_id = $2 FOR UPDATE`, [appId, openId],
      );
      const userId = sandboxUserIdValue(input.sandboxUserId
        ?? (existingIdentity.rows[0] ? String(existingIdentity.rows[0].sandbox_user_id) : randomUUID()));
      if (existingIdentity.rows[0] && String(existingIdentity.rows[0].sandbox_user_id) !== userId) {
        throw new SandboxUserLookupError('identity_conflict', 'legacy identity is already bound to another sandbox user');
      }
      const userResult = await tx.query<Record<string, unknown>>(
        `INSERT INTO sandbox_users (sandbox_user_id, enabled, can_openmemory, execution_mode)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (sandbox_user_id) DO UPDATE SET updated_at = now()
         RETURNING sandbox_user_id, enabled, can_openmemory, execution_mode, pod_generation, created_at, updated_at`,
        [userId, boolValue(source.enabled, true), boolValue(source.can_openmemory), source.execution_mode === 'native' ? 'native' : 'podman'],
      );
      const identityResult = await tx.query<Record<string, unknown>>(
        `INSERT INTO sandbox_user_identities (sandbox_user_id, lark_app_id, open_id, enabled)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (lark_app_id, open_id) DO UPDATE SET
           sandbox_user_id = EXCLUDED.sandbox_user_id,
           enabled = EXCLUDED.enabled, updated_at = now()
         RETURNING sandbox_user_id, lark_app_id, open_id, enabled, created_at, updated_at`,
        [userId, appId, openId, boolValue(source.enabled, true)],
      );
      const oldCredential = await tx.query<Record<string, unknown>>(
        `SELECT credential_kind, base_url, model, encrypted_secret, secret_nonce, credential_version
           FROM agent_model_credentials WHERE lark_app_id = $1 AND open_id = $2`, [appId, openId],
      );
      let migratedCredential = false;
      if (oldCredential.rows[0]) {
        const old = oldCredential.rows[0];
        const existingNew = await tx.query<Record<string, unknown>>(
          `SELECT sandbox_user_id FROM sandbox_user_credentials WHERE sandbox_user_id = $1 AND harness = $2`, [userId, harness],
        );
        if (!existingNew.rows[0]) {
          const credentialKind = String(old.credential_kind) as PodmanCredentialKind;
          try { assertCredentialCompatible(harness as PodmanCliId, credentialKind); } catch {
            throw new SandboxUserLookupError('credential_incompatible', 'legacy credential is incompatible with the requested harness');
          }
          const version = Number(old.credential_version);
          const baseUrl = typeof old.base_url === 'string' ? old.base_url : undefined;
          const model = typeof old.model === 'string' ? old.model : undefined;
          const oldSecret = decryptCredentialUtf8(
            { ciphertext: bytes(old.encrypted_secret), nonce: bytes(old.secret_nonce) },
            masterKey,
            { larkAppId: appId, openId },
          );
          const encrypted = encryptSandboxUserCredential(oldSecret, masterKey, {
            sandboxUserId: userId,
            harness,
            baseUrl,
            model,
            credentialVersion: version,
          });
          await tx.query(
            `INSERT INTO sandbox_user_credentials
               (sandbox_user_id, harness, credential_kind, base_url, model, encrypted_secret, secret_nonce, credential_version)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [userId, harness, credentialKind, baseUrl ?? null, model ?? null, encrypted.ciphertext, encrypted.nonce, version],
          );
          migratedCredential = true;
        }
      }
      return {
        user: parseUser(userResult.rows[0]!),
        identity: parseIdentity(identityResult.rows[0]!),
        migratedCredential,
      };
    });
  }

  async getCredential(user: SandboxUserKey, harnessInput: SandboxUserHarness): Promise<SandboxUserCredentialMetadata | undefined> {
    const userId = sandboxUserIdValue(user.sandboxUserId);
    const harness = harnessValue(harnessInput);
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `SELECT sandbox_user_id, harness, credential_kind, base_url, model, credential_version, updated_at
           FROM sandbox_user_credentials WHERE sandbox_user_id = $1 AND harness = $2`, [userId, harness],
      );
      if (!result.rows[0]) return undefined;
      const row = result.rows[0];
      return {
        sandboxUserId: String(row.sandbox_user_id), harness: harnessValue(row.harness),
        credentialKind: String(row.credential_kind) as PodmanCredentialKind,
        ...(typeof row.base_url === 'string' ? { baseUrl: row.base_url } : {}),
        ...(typeof row.model === 'string' ? { model: row.model } : {}),
        credentialVersion: Number(row.credential_version), updatedAt: dateValue(row.updated_at),
      };
    } catch (error) { throw dbError(error); }
  }

  async putCredential(input: {
    readonly user: SandboxUserKey;
    readonly harness: SandboxUserHarness;
    readonly credentialKind: PodmanCredentialKind;
    readonly secret: string | Buffer;
    readonly baseUrl?: string;
    readonly model?: string;
    readonly expectedVersion?: number;
  }): Promise<SandboxUserCredentialMetadata> {
    const userId = sandboxUserIdValue(input.user.sandboxUserId);
    const harness = harnessValue(input.harness);
    if (!this.masterKey) throw new SandboxUserLookupError('database_unavailable', 'credential master key is not configured');
    const secret = ensureCredentialShape(input);
    return withTransaction(this.db, async tx => {
      const owner = await tx.query<Record<string, unknown>>(
        `SELECT enabled FROM sandbox_users WHERE sandbox_user_id = $1 FOR UPDATE`, [userId],
      );
      if (!owner.rows[0]) throw new SandboxUserLookupError('not_found', 'sandbox user is not registered');
      if (!boolValue(owner.rows[0].enabled)) throw new SandboxUserLookupError('disabled', 'sandbox user is disabled');
      const current = await tx.query<Record<string, unknown>>(
        `SELECT credential_version FROM sandbox_user_credentials WHERE sandbox_user_id = $1 AND harness = $2 FOR UPDATE`, [userId, harness],
      );
      const actual = current.rows[0] ? Number(current.rows[0].credential_version) : undefined;
      if (input.expectedVersion !== undefined && (actual ?? 0) !== input.expectedVersion) {
        throw new SandboxCredentialVersionConflictError(input.expectedVersion, actual);
      }
      const version = actual === undefined ? 1 : actual + 1;
      const encrypted = encryptSandboxUserCredential(secret, this.masterKey!, {
        sandboxUserId: userId, harness, baseUrl: input.baseUrl, model: input.model, credentialVersion: version,
      });
      const result = await tx.query<Record<string, unknown>>(
        `INSERT INTO sandbox_user_credentials
           (sandbox_user_id, harness, credential_kind, base_url, model, encrypted_secret, secret_nonce, credential_version)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (sandbox_user_id, harness) DO UPDATE SET
           credential_kind = EXCLUDED.credential_kind, base_url = EXCLUDED.base_url, model = EXCLUDED.model,
           encrypted_secret = EXCLUDED.encrypted_secret, secret_nonce = EXCLUDED.secret_nonce,
           credential_version = EXCLUDED.credential_version, updated_at = now()
         RETURNING sandbox_user_id, harness, credential_kind, base_url, model, credential_version, updated_at`,
        [userId, harness, input.credentialKind, input.baseUrl ?? null, input.model ?? null, encrypted.ciphertext, encrypted.nonce, version],
      );
      const row = result.rows[0]!;
      return {
        sandboxUserId: String(row.sandbox_user_id), harness: harnessValue(row.harness),
        credentialKind: String(row.credential_kind) as PodmanCredentialKind,
        ...(typeof row.base_url === 'string' ? { baseUrl: row.base_url } : {}),
        ...(typeof row.model === 'string' ? { model: row.model } : {}),
        credentialVersion: Number(row.credential_version), updatedAt: dateValue(row.updated_at),
        keyFingerprint: credentialFingerprint(secret),
      };
    });
  }

  async readSecret(user: SandboxUserKey, harnessInput: SandboxUserHarness, expectedVersion?: number): Promise<{ metadata: SandboxUserCredentialMetadata; secret: string }> {
    const userId = sandboxUserIdValue(user.sandboxUserId);
    const harness = harnessValue(harnessInput);
    if (!this.masterKey) throw new SandboxUserLookupError('database_unavailable', 'credential master key is not configured');
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `SELECT sandbox_user_id, harness, credential_kind, base_url, model, encrypted_secret, secret_nonce, credential_version, updated_at
           FROM sandbox_user_credentials WHERE sandbox_user_id = $1 AND harness = $2`, [userId, harness],
      );
      if (!result.rows[0]) throw new SandboxUserLookupError('credential_missing', 'sandbox user credential is not configured');
      const record = parseCredential(result.rows[0]);
      if (expectedVersion !== undefined && record.credentialVersion !== expectedVersion) {
        throw new SandboxCredentialVersionConflictError(expectedVersion, record.credentialVersion);
      }
      const secret = decryptSandboxUserCredentialUtf8(
        { ciphertext: record.encryptedSecret, nonce: record.secretNonce }, this.masterKey, {
          sandboxUserId: userId, harness, baseUrl: record.baseUrl, model: record.model, credentialVersion: record.credentialVersion,
        },
      );
      const { encryptedSecret: _encrypted, secretNonce: _nonce, ...metadata } = record;
      return { metadata, secret };
    } catch (error) {
      if (error instanceof SandboxUserLookupError || error instanceof SandboxCredentialVersionConflictError) throw error;
      throw dbError(error);
    }
  }

  async deleteCredential(user: SandboxUserKey, harnessInput: SandboxUserHarness, expectedVersion?: number): Promise<boolean> {
    const userId = sandboxUserIdValue(user.sandboxUserId);
    const harness = harnessValue(harnessInput);
    return withTransaction(this.db, async tx => {
      const result = await tx.query(
        `DELETE FROM sandbox_user_credentials WHERE sandbox_user_id = $1 AND harness = $2${expectedVersion === undefined ? '' : ' AND credential_version = $3'}`,
        expectedVersion === undefined ? [userId, harness] : [userId, harness, expectedVersion],
      );
      if (expectedVersion !== undefined && Number(result.rowCount ?? 0) === 0) {
        const current = await tx.query<Record<string, unknown>>(
          `SELECT credential_version FROM sandbox_user_credentials WHERE sandbox_user_id = $1 AND harness = $2`, [userId, harness],
        );
        if (current.rows[0]) throw new SandboxCredentialVersionConflictError(expectedVersion, Number(current.rows[0].credential_version));
      }
      return Number(result.rowCount ?? 0) > 0;
    });
  }

  async createRuntime(input: {
    readonly sandboxUserId: string;
    readonly sessionId: string;
    readonly podGeneration: number;
    readonly harness: SandboxUserHarness;
    readonly imageDigest: string;
    readonly runtimeId?: string;
    readonly containerName?: string;
    readonly workspacePath?: string;
    readonly homePath?: string;
    readonly credentialVersion?: number;
    readonly sourceRepo?: string;
    readonly sourceBranch?: string;
  }): Promise<SandboxPodRuntimeManifest> {
    const userId = sandboxUserIdValue(input.sandboxUserId);
    const runtimeId = textValue(input.runtimeId ?? randomUUID(), 'runtimeId');
    const sessionId = textValue(input.sessionId, 'sessionId');
    const podGeneration = input.podGeneration;
    const harness = harnessValue(input.harness);
    const imageDigest = textValue(input.imageDigest, 'imageDigest');
    safeRuntimeInput({ ...input, runtimeId, sessionId, podGeneration, imageDigest });
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `INSERT INTO sandbox_pod_runtime_manifests
           (runtime_id, sandbox_user_id, session_id, pod_generation, harness, state, image_digest, container_name,
            workspace_path, home_path, credential_version, source_repo, source_branch, manifest)
         VALUES ($1, $2, $3, $4, $5, 'provisioning', $6, $7, $8, $9, $10, $11, $12,
                 jsonb_build_object('schemaVersion', 2, 'runtimeId', $1::text, 'sessionId', $3::text,
                   'sandboxUserId', $2::text, 'podGeneration', $4::bigint,
                   'harness', $5::text, 'imageDigest', $6::text))
         RETURNING runtime_id, sandbox_user_id, session_id, pod_generation, harness, state, image_digest, container_name,
                   workspace_path, home_path, credential_version, source_repo, source_branch,
                   created_at, updated_at, stopped_at, failure_code`,
        [runtimeId, userId, sessionId, podGeneration, harness, imageDigest, input.containerName ?? null, input.workspacePath ?? null,
          input.homePath ?? null, input.credentialVersion ?? null, input.sourceRepo ?? null, input.sourceBranch ?? null],
      );
      return parseRuntime(result.rows[0]!);
    } catch (error) { throw dbError(error); }
  }

  async getRuntime(runtimeIdInput: string): Promise<SandboxPodRuntimeManifest | undefined> {
    const runtimeId = textValue(runtimeIdInput, 'runtimeId');
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `SELECT runtime_id, sandbox_user_id, session_id, pod_generation, harness, state, image_digest, container_name,
                workspace_path, home_path, credential_version, source_repo, source_branch,
           created_at, updated_at, stopped_at, failure_code
           FROM sandbox_pod_runtime_manifests WHERE runtime_id = $1`, [runtimeId],
      );
      return result.rows[0] ? parseRuntime(result.rows[0]) : undefined;
    } catch (error) { throw dbError(error); }
  }

  /** Locate a cold manifest when a rolling upgrade changed the deterministic runtime id. */
  async getRuntimeForSession(input: { readonly sessionId: string; readonly podGeneration: number }): Promise<SandboxPodRuntimeManifest | undefined> {
    const sessionId = textValue(input.sessionId, 'sessionId');
    if (!Number.isSafeInteger(input.podGeneration) || input.podGeneration < 1) {
      throw new TypeError('podGeneration must be a positive integer');
    }
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `SELECT runtime_id, sandbox_user_id, session_id, pod_generation, harness, state, image_digest, container_name,
                workspace_path, home_path, credential_version, source_repo, source_branch,
                created_at, updated_at, stopped_at, failure_code
           FROM sandbox_pod_runtime_manifests
          WHERE session_id = $1 AND pod_generation = $2`, [sessionId, input.podGeneration],
      );
      return result.rows[0] ? parseRuntime(result.rows[0]) : undefined;
    } catch (error) { throw dbError(error); }
  }

  /** Update lifecycle state while retaining the manifest for cold-start recovery. */
  async updateRuntimeState(input: {
    readonly runtimeId: string;
    readonly state: SandboxRuntimeState;
    readonly expectedState?: SandboxRuntimeState;
    readonly failureCode?: string;
  }): Promise<SandboxPodRuntimeManifest> {
    const runtimeId = textValue(input.runtimeId, 'runtimeId');
    const state = stateValue(input.state);
    const failureCode = input.failureCode === undefined ? undefined : textValue(input.failureCode, 'failureCode');
    return withTransaction(this.db, async tx => {
      const current = await tx.query<Record<string, unknown>>(
        `SELECT runtime_id, sandbox_user_id, session_id, pod_generation, harness, state, image_digest, container_name,
                workspace_path, home_path, credential_version, source_repo, source_branch,
                created_at, updated_at, stopped_at, failure_code
           FROM sandbox_pod_runtime_manifests WHERE runtime_id = $1 FOR UPDATE`, [runtimeId],
      );
      if (!current.rows[0]) throw new SandboxUserLookupError('not_found', 'sandbox runtime manifest is not registered');
      const actual = stateValue(current.rows[0].state);
      if (input.expectedState !== undefined && actual !== input.expectedState) {
        throw new SandboxRuntimeStateConflictError(runtimeId, input.expectedState, actual);
      }
      const result = await tx.query<Record<string, unknown>>(
        `UPDATE sandbox_pod_runtime_manifests
            SET state = $2, failure_code = $3,
                stopped_at = CASE WHEN $2 IN ('stopped', 'failed') THEN COALESCE(stopped_at, now()) ELSE NULL END,
                updated_at = now()
          WHERE runtime_id = $1
        RETURNING runtime_id, sandbox_user_id, session_id, pod_generation, harness, state, image_digest, container_name,
                  workspace_path, home_path, credential_version, source_repo, source_branch,
                  created_at, updated_at, stopped_at, failure_code`,
        [runtimeId, state, failureCode ?? null],
      );
      return parseRuntime(result.rows[0]!);
    });
  }

  async listUserRuntimes(user: SandboxUserKey, states?: readonly SandboxRuntimeState[]): Promise<readonly SandboxPodRuntimeManifest[]> {
    const userId = sandboxUserIdValue(user.sandboxUserId);
    const normalized = states?.map(stateValue);
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `SELECT runtime_id, sandbox_user_id, session_id, pod_generation, harness, state, image_digest, container_name,
                workspace_path, home_path, credential_version, source_repo, source_branch,
                created_at, updated_at, stopped_at, failure_code
           FROM sandbox_pod_runtime_manifests
          WHERE sandbox_user_id = $1
            AND ($2::text[] IS NULL OR state = ANY($2::text[]))
          ORDER BY updated_at DESC`, [userId, normalized && normalized.length > 0 ? normalized : null],
      );
      return result.rows.map(parseRuntime);
    } catch (error) { throw dbError(error); }
  }
}
