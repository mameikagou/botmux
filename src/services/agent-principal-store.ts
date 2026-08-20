/** PostgreSQL authority for shared-sandbox principals and BYOK credentials. */
import { createRequire } from 'node:module';
import { validateApiCredentialInput, type ApiCredentialInput } from './agent-credential-policy.js';
import {
  credentialFingerprint,
  decryptCredentialUtf8,
  encryptCredential,
} from './agent-principal-crypto.js';
import { assertCredentialCompatible, type PodmanCliId, type PodmanCredentialKind } from '../execution/podman-execution.js';
import {
  AGENT_PRINCIPAL_SKILLS_UP_SQL,
  ensureDefaultPrincipalSkillRows,
  discoverDefaultPrincipalSkills,
  freezePrincipalSkillRows,
  readPrincipalSkillRows,
  replacePrincipalSkillRows,
  type FrozenPrincipalSkillBinding,
  type AgentPrincipalSkillRow,
} from './agent-principal-skills.js';
import type {
  SandboxUserHarness,
  SandboxUserIdentityRow,
  SandboxUserRegistryRepository,
  SandboxUserRow,
} from './sandbox-user-registry.js';

export const AGENT_PRINCIPAL_MIGRATION_ID = '20260819_agent_principals_v1';

export interface SqlResult<Row = Record<string, unknown>> {
  readonly rows: Row[];
  readonly rowCount?: number;
}

export interface SqlExecutor {
  query<Row = Record<string, unknown>>(text: string, values?: readonly unknown[]): Promise<SqlResult<Row>>;
}

export interface SqlTransaction extends SqlExecutor {
  release(): void;
}

export interface SqlPool extends SqlExecutor {
  connect(): Promise<SqlTransaction>;
  end?(): Promise<void>;
}

export interface AgentPrincipalKey {
  readonly larkAppId: string;
  readonly openId: string;
}

/** Where a new topic for this app-scoped principal is allowed to execute. */
export type AgentExecutionMode = 'native' | 'podman';

export interface AgentPrincipalRow extends AgentPrincipalKey {
  readonly enabled: boolean;
  readonly canOpenMemory: boolean;
  readonly executionMode: AgentExecutionMode;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface AgentCredentialMetadata extends AgentPrincipalKey {
  readonly credentialKind: PodmanCredentialKind;
  readonly baseUrl?: string;
  readonly model?: string;
  readonly credentialVersion: number;
  readonly updatedAt: string;
  readonly keyFingerprint?: string;
}

export interface AgentCredentialRecord extends AgentCredentialMetadata {
  readonly encryptedSecret: Buffer;
  readonly secretNonce: Buffer;
}

export interface AgentCodexLoginTaskRecord {
  readonly taskId: string;
  readonly key: AgentPrincipalKey;
  readonly status: 'pending' | 'ready' | 'failed' | 'logged_out' | 'expired';
  readonly leaseExpiresAt: string;
  readonly verificationUri?: string;
  readonly userCode?: string;
  readonly errorCode?: string;
}

/** Session-persisted and non-secret. Never add the decrypted secret here. */
export interface FrozenPrincipalBinding extends AgentPrincipalKey {
  readonly enabled: true;
  readonly canOpenMemory: boolean;
  readonly cliId: PodmanCliId;
  readonly credentialVersion: number;
  readonly credentialKind: PodmanCredentialKind;
  /** V4 stable user/pod identity. Both fields are required for guests. */
  readonly sandboxUserId?: string;
  readonly podGeneration?: number;
  readonly ownerOpenId?: string;
  /** Skill leaves read once at new-instance ingress and frozen with the topic. */
  readonly skills?: readonly FrozenPrincipalSkillBinding[];
}

/** Optional V4 authority injected by production callers. Keeping this as a
 * structural interface lets old test/rolling callers retain the V3 path while
 * every V4 runtime uses the stable user tables. */
export type StableSandboxUserRegistry = Pick<
  SandboxUserRegistryRepository,
  'resolveUserForIdentity' | 'readSecret' | 'getCredential' | 'putCredential' | 'deleteCredential'
>;

/** Session-persisted credential metadata. */
export interface FrozenCredentialBinding {
  readonly kind: PodmanCredentialKind;
  readonly credentialVersion: number;
  readonly baseUrl?: string;
  readonly model?: string;
}

export type AgentPrincipalLookupFailureCode = 'not_found' | 'disabled' | 'credential_missing' | 'credential_incompatible' | 'database_unavailable';

export class AgentPrincipalLookupError extends Error {
  readonly code: AgentPrincipalLookupFailureCode;
  constructor(code: AgentPrincipalLookupFailureCode, message: string = code) {
    super(message);
    this.name = 'AgentPrincipalLookupError';
    this.code = code;
  }
}

export class CredentialVersionConflictError extends Error {
  readonly expectedVersion: number;
  readonly actualVersion?: number;
  constructor(expectedVersion: number, actualVersion?: number) {
    super('credential_version_conflict');
    this.name = 'CredentialVersionConflictError';
    this.expectedVersion = expectedVersion;
    this.actualVersion = actualVersion;
  }
}

export class CodexLoginTaskConflictError extends Error {
  constructor() {
    super('codex_login_task_conflict');
    this.name = 'CodexLoginTaskConflictError';
  }
}

/**
 * Domain errors that have already crossed our sanitization boundary. Every
 * other error in a transaction may be a driver/SQL error and must be reduced
 * to the generic database-unavailable result before it reaches a caller.
 */
function isSanitizedDomainError(
  error: unknown,
): error is AgentPrincipalLookupError | CredentialVersionConflictError | CodexLoginTaskConflictError {
  return error instanceof AgentPrincipalLookupError
    || error instanceof CredentialVersionConflictError
    || error instanceof CodexLoginTaskConflictError;
}

export const AGENT_PRINCIPAL_UP_SQL = `
CREATE TABLE IF NOT EXISTS agent_principals (
  lark_app_id text NOT NULL,
  open_id text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  can_openmemory boolean NOT NULL DEFAULT false,
  execution_mode text NOT NULL DEFAULT 'podman' CHECK (execution_mode IN ('native', 'podman')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (lark_app_id, open_id),
  CHECK (length(trim(lark_app_id)) > 0),
  CHECK (length(trim(open_id)) > 0)
);
ALTER TABLE agent_principals
  ADD COLUMN IF NOT EXISTS execution_mode text NOT NULL DEFAULT 'podman';
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'agent_principals'::regclass
      AND conname = 'agent_principals_execution_mode_check'
  ) THEN
    ALTER TABLE agent_principals
      ADD CONSTRAINT agent_principals_execution_mode_check
      CHECK (execution_mode IN ('native', 'podman'));
  END IF;
END $$;
`;

export const AGENT_CREDENTIAL_UP_SQL = `
CREATE TABLE IF NOT EXISTS agent_model_credentials (
  lark_app_id text NOT NULL,
  open_id text NOT NULL,
  credential_kind text NOT NULL CHECK (credential_kind IN ('codex_chatgpt', 'api')),
  base_url text,
  model text,
  encrypted_secret bytea NOT NULL,
  secret_nonce bytea NOT NULL,
  credential_version bigint NOT NULL DEFAULT 1 CHECK (credential_version > 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (lark_app_id, open_id),
  FOREIGN KEY (lark_app_id, open_id)
    REFERENCES agent_principals (lark_app_id, open_id)
    ON UPDATE CASCADE ON DELETE CASCADE,
  CHECK ((credential_kind = 'api' AND length(trim(coalesce(base_url, ''))) > 0 AND length(trim(coalesce(model, ''))) > 0)
      OR (credential_kind = 'codex_chatgpt' AND base_url IS NULL AND model IS NULL))
);
`;

/** Login tasks are narrow, short-lived coordination state, never auth data. */
export const AGENT_LOGIN_TASK_UP_SQL = `
CREATE TABLE IF NOT EXISTS agent_codex_login_tasks (
  task_id uuid PRIMARY KEY,
  lark_app_id text NOT NULL,
  open_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('pending', 'ready', 'failed', 'logged_out', 'expired')),
  lease_expires_at timestamptz NOT NULL,
  verification_uri text,
  user_code text,
  error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (lark_app_id, open_id)
    REFERENCES agent_principals (lark_app_id, open_id)
    ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS agent_codex_login_tasks_live_idx
  ON agent_codex_login_tasks (lark_app_id, open_id)
  WHERE status = 'pending';
`;

export const AGENT_PRINCIPAL_DOWN_SQL = `
DROP TABLE IF EXISTS agent_principal_skills;
DROP TABLE IF EXISTS agent_codex_login_tasks;
DROP TABLE IF EXISTS agent_model_credentials;
DROP TABLE IF EXISTS agent_principals;
`;

async function withAgentPrincipalTransaction<T>(db: SqlExecutor, operation: (tx: SqlExecutor) => Promise<T>): Promise<T> {
  // PostgreSQL transactions are connection-scoped.  A Pool's `query` method
  // may dispatch each statement to a different idle connection, so migrations
  // and login-task fencing must pin one client for their whole transaction.
  const connect = (db as Partial<SqlPool>).connect;
  if (typeof connect === 'function') {
    let client: SqlTransaction;
    try {
      client = await connect.call(db);
    } catch (error) {
      throw toDbError(error);
    }
    try {
      await client.query('BEGIN');
      const result = await operation(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      if (isSanitizedDomainError(error)) throw error;
      throw toDbError(error);
    } finally {
      client.release();
    }
  }
  await db.query('BEGIN');
  try {
    const result = await operation(db);
    await db.query('COMMIT');
    return result;
  } catch (error) {
    await db.query('ROLLBACK').catch(() => undefined);
    if (isSanitizedDomainError(error)) throw error;
    throw toDbError(error);
  }
}

export async function applyAgentPrincipalMigration(db: SqlExecutor): Promise<void> {
  await withAgentPrincipalTransaction(db, async tx => {
    // All daemon/dashboard processes may cold-start together. Serialize the
    // additive DDL and its constraint checks on one database-wide advisory
    // transaction lock so two first boots cannot race an ALTER/DO block.
    await tx.query(`SELECT pg_advisory_xact_lock(hashtext('botmux:agent-principal-migrations'))`);
    await tx.query(AGENT_PRINCIPAL_UP_SQL);
    await tx.query(AGENT_CREDENTIAL_UP_SQL);
    await tx.query(AGENT_LOGIN_TASK_UP_SQL);
    await tx.query(AGENT_PRINCIPAL_SKILLS_UP_SQL);
  });
}

export async function rollbackAgentPrincipalMigration(db: SqlExecutor): Promise<void> {
  await withAgentPrincipalTransaction(db, tx => tx.query(AGENT_PRINCIPAL_DOWN_SQL).then(() => undefined));
}

function textKey(value: string, name: string): string {
  if (typeof value !== 'string' || value.trim() === '' || /[\u0000\r\n]/u.test(value)) {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value.trim();
}

function keyValues(key: AgentPrincipalKey): [string, string] {
  return [textKey(key.larkAppId, 'larkAppId'), textKey(key.openId, 'openId')];
}

function boolValue(raw: unknown, fallback = false): boolean {
  return typeof raw === 'boolean' ? raw : raw === 't' ? true : raw === 'f' ? false : fallback;
}

function executionModeValue(raw: unknown): AgentExecutionMode {
  // Rows created before the mode column was introduced are deliberately
  // treated as Podman. This preserves the existing isolation posture during
  // a rolling migration and never upgrades a legacy principal to host access.
  return raw === 'native' ? 'native' : 'podman';
}

function dateValue(raw: unknown): string {
  return raw instanceof Date ? raw.toISOString() : typeof raw === 'string' ? raw : new Date(0).toISOString();
}

function parsePrincipal(row: Record<string, unknown>): AgentPrincipalRow {
  return {
    larkAppId: String(row.lark_app_id),
    openId: String(row.open_id),
    enabled: boolValue(row.enabled),
    canOpenMemory: boolValue(row.can_openmemory),
    executionMode: executionModeValue(row.execution_mode),
    createdAt: dateValue(row.created_at),
    updatedAt: dateValue(row.updated_at),
  };
}

function parseCredential(row: Record<string, unknown>): AgentCredentialRecord {
  const bytes = (value: unknown): Buffer => {
    if (Buffer.isBuffer(value)) return value;
    if (value instanceof Uint8Array) return Buffer.from(value);
    if (typeof value === 'string') {
      // node-postgres normally returns bytea as Buffer, but a few test and
      // proxy adapters expose it as hex text.
      const hex = value.startsWith('\\x') ? value.slice(2) : value;
      if (/^[0-9a-f]+$/iu.test(hex) && hex.length % 2 === 0) return Buffer.from(hex, 'hex');
      return Buffer.from(value, 'base64');
    }
    throw new TypeError('credential bytes are invalid');
  };
  const encryptedSecret = bytes(row.encrypted_secret);
  const secretNonce = bytes(row.secret_nonce);
  return {
    larkAppId: String(row.lark_app_id),
    openId: String(row.open_id),
    credentialKind: String(row.credential_kind) as PodmanCredentialKind,
    ...(typeof row.base_url === 'string' ? { baseUrl: row.base_url } : {}),
    ...(typeof row.model === 'string' ? { model: row.model } : {}),
    credentialVersion: Number(row.credential_version),
    updatedAt: dateValue(row.updated_at),
    encryptedSecret,
    secretNonce,
  };
}

function parseLoginTask(row: Record<string, unknown>): AgentCodexLoginTaskRecord {
  const status = String(row.status);
  if (status !== 'pending' && status !== 'ready' && status !== 'failed' && status !== 'logged_out' && status !== 'expired') {
    throw new TypeError('invalid Codex login task status');
  }
  return {
    taskId: String(row.task_id),
    key: { larkAppId: String(row.lark_app_id), openId: String(row.open_id) },
    status,
    leaseExpiresAt: dateValue(row.lease_expires_at),
    ...(typeof row.verification_uri === 'string' ? { verificationUri: row.verification_uri } : {}),
    ...(typeof row.user_code === 'string' ? { userCode: row.user_code } : {}),
    ...(typeof row.error_code === 'string' ? { errorCode: row.error_code } : {}),
  };
}

function decodePrincipalSkills(raw: unknown): readonly FrozenPrincipalSkillBinding[] {
  if (raw === undefined || raw === null) return discoverDefaultPrincipalSkills();
  let parsed: unknown = raw;
  if (typeof raw === 'string') {
    try { parsed = JSON.parse(raw); } catch { return []; }
  }
  if (!Array.isArray(parsed)) return [];
  const rows: AgentPrincipalSkillRow[] = [];
  for (const item of parsed) {
    if (!item || typeof item !== 'object') continue;
    try {
      const row = item as Record<string, unknown>;
      rows.push({
        larkAppId: String(row.lark_app_id ?? ''),
        openId: String(row.open_id ?? ''),
        name: String(row.skill_name ?? ''),
        rootDir: String(row.skill_root ?? ''),
        enabled: boolValue(row.enabled, true),
        priority: Number(row.priority ?? 100),
        createdAt: dateValue(row.created_at),
        updatedAt: dateValue(row.updated_at),
      });
    } catch {
      // A malformed optional row must not widen the launch boundary.
    }
  }
  return freezePrincipalSkillRows(rows);
}

function toDbError(error: unknown): AgentPrincipalLookupError | CredentialVersionConflictError {
  // Repository policy failures are already sanitized and meaningful to the
  // caller. Do not turn a disabled/not-found principal into a misleading
  // database outage merely because the surrounding operation has a generic
  // error boundary.
  if (error instanceof AgentPrincipalLookupError) return error;
  if (error instanceof CredentialVersionConflictError) return error;
  const stableCode = error && typeof error === 'object' && 'code' in error
    ? (error as { code?: unknown }).code : undefined;
  if (stableCode === 'not_found' || stableCode === 'disabled'
    || stableCode === 'credential_missing' || stableCode === 'credential_incompatible') {
    const code = stableCode as AgentPrincipalLookupFailureCode;
    return new AgentPrincipalLookupError(code, `sandbox user ${code.replace('_', ' ')}`);
  }
  return new AgentPrincipalLookupError(
    'database_unavailable',
    // Never copy a driver error to a bot/dashboard boundary: libpq messages
    // can include a full postgres:// DSN (and therefore a password). Keep the
    // diagnostic deliberately generic; operators can inspect the DB service.
    'agent principal database unavailable',
  );
}

export class AgentPrincipalRepository {
  private readonly stableRegistry?: StableSandboxUserRegistry;

  constructor(
    private readonly db: SqlPool,
    private readonly masterKey?: Buffer,
    stableRegistry?: StableSandboxUserRegistry,
  ) {
    this.stableRegistry = stableRegistry;
  }

  private async resolveStableUser(key: AgentPrincipalKey): Promise<{
    readonly user: SandboxUserRow;
    readonly identity: SandboxUserIdentityRow;
  } | undefined> {
    if (!this.stableRegistry) return undefined;
    return this.stableRegistry.resolveUserForIdentity(key);
  }

  private static harnessForCli(cliId: string): SandboxUserHarness {
    if (cliId === 'codex') return 'codex';
    if (cliId === 'claude-code') return 'claude-code';
    if (cliId === 'pi') return 'pi';
    if (cliId === 'opencode') return 'opencode';
    throw new AgentPrincipalLookupError('credential_incompatible', 'model credential is incompatible with this fixed bot harness');
  }

  private static principalFromStableUser(
    user: SandboxUserRow,
    identity: SandboxUserIdentityRow,
  ): AgentPrincipalRow {
    return {
      larkAppId: identity.larkAppId,
      openId: identity.openId,
      enabled: user.enabled && identity.enabled,
      canOpenMemory: user.canOpenMemory,
      executionMode: user.executionMode,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  async getPrincipal(key: AgentPrincipalKey): Promise<AgentPrincipalRow | undefined> {
    const [appId, openId] = keyValues(key);
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `SELECT lark_app_id, open_id, enabled, can_openmemory, execution_mode, created_at, updated_at
           FROM agent_principals WHERE lark_app_id = $1 AND open_id = $2`,
        [appId, openId],
      );
      return result.rows[0] ? parsePrincipal(result.rows[0]) : undefined;
    } catch (error) {
      throw toDbError(error);
    }
  }

  /** Read the explicit skill snapshot for a new topic. Existing topics retain
   * their Session copy and never call this method for ordinary messages. */
  async getPrincipalSkills(key: AgentPrincipalKey): Promise<readonly FrozenPrincipalSkillBinding[]> {
    // These operator-approved skills are mandatory for every principal.
    // Seed them at the same new-instance boundary so principals created after
    // the initial deployment also get durable DB rows before their snapshot is
    // frozen. ON CONFLICT preserves any existing per-principal metadata.
    await ensureDefaultPrincipalSkillRows(this.db, key);
    const rows = await readPrincipalSkillRows(this.db, key);
    return freezePrincipalSkillRows(rows);
  }

  /** Persist the operator-approved skill leaves for one app-scoped principal. */
  async replacePrincipalSkills(
    key: AgentPrincipalKey,
    rows: readonly Pick<AgentPrincipalSkillRow, 'name' | 'rootDir' | 'enabled' | 'priority'>[],
  ): Promise<readonly FrozenPrincipalSkillBinding[]> {
    const persisted = await replacePrincipalSkillRows(this.db, key, rows);
    return freezePrincipalSkillRows(persisted);
  }

  /** Seed the default skills without overwriting a custom principal list. */
  async ensureDefaultPrincipalSkills(key: AgentPrincipalKey): Promise<void> {
    await ensureDefaultPrincipalSkillRows(this.db, key);
  }

  async getCredential(key: AgentPrincipalKey, harnessInput?: SandboxUserHarness): Promise<AgentCredentialRecord | undefined> {
    const [appId, openId] = keyValues(key);
    try {
      // Credential reads are principal operations too. Keep the repository
      // fail-closed even when a caller bypasses the narrow dashboard API.
      await this.requireEnabled(this.db, key);
      if (this.stableRegistry) {
        let stable: { user: SandboxUserRow; identity: SandboxUserIdentityRow } | undefined;
        try {
          stable = await this.resolveStableUser(key);
        } catch (error) {
          if ((error as { code?: unknown } | undefined)?.code !== 'not_found') throw error;
        }
        if (stable) {
          const harness = harnessInput ?? 'codex';
          const metadata = await this.stableRegistry.getCredential({ sandboxUserId: stable.user.sandboxUserId }, harness);
          if (!metadata) return undefined;
          return {
            larkAppId: key.larkAppId,
            openId: key.openId,
            credentialKind: metadata.credentialKind,
            ...(metadata.baseUrl ? { baseUrl: metadata.baseUrl } : {}),
            ...(metadata.model ? { model: metadata.model } : {}),
            credentialVersion: metadata.credentialVersion,
            updatedAt: metadata.updatedAt,
            encryptedSecret: Buffer.alloc(0),
            secretNonce: Buffer.alloc(0),
          };
        }
      }
      const result = await this.db.query<Record<string, unknown>>(
        `SELECT lark_app_id, open_id, credential_kind, base_url, model,
                encrypted_secret, secret_nonce, credential_version, updated_at
           FROM agent_model_credentials WHERE lark_app_id = $1 AND open_id = $2`,
        [appId, openId],
      );
      return result.rows[0] ? parseCredential(result.rows[0]) : undefined;
    } catch (error) {
      throw toDbError(error);
    }
  }

  /** Resolve only the non-secret launch posture for a new topic. */
  async resolveExecutionModeForNewInstance(input: {
    readonly key: AgentPrincipalKey;
    readonly ownerOpenId?: string;
  }): Promise<{ principal: AgentPrincipalRow; executionMode: AgentExecutionMode; sandboxUserId?: string; podGeneration?: number; principalSkills: readonly FrozenPrincipalSkillBinding[] }> {
    const key = { larkAppId: textKey(input.key.larkAppId, 'larkAppId'), openId: textKey(input.key.openId, 'openId') };

    // V4 stable identity is the ingress authority for guest users. A missing
    // mapping is a deliberate fail-closed result; the legacy lookup below is
    // retained only for owner-native identities and rolling V3 callers that
    // did not inject the V4 registry yet.
    if (this.stableRegistry) {
      try {
        const stable = await this.resolveStableUser(key);
        if (stable) {
          const principal = AgentPrincipalRepository.principalFromStableUser(stable.user, stable.identity);
          if (!principal.enabled) throw new AgentPrincipalLookupError('disabled', 'sandbox user identity is disabled');
          if (input.ownerOpenId && input.ownerOpenId !== principal.openId) {
            throw new AgentPrincipalLookupError('disabled', 'session owner does not match the requesting principal');
          }
          return {
            principal,
            executionMode: principal.executionMode,
            sandboxUserId: stable.user.sandboxUserId,
            podGeneration: stable.user.podGeneration,
            principalSkills: await this.getPrincipalSkills(key),
          };
        }
      } catch (error) {
        // The stable repository reports not_found for an owner identity that
        // is intentionally outside the guest registry. Only that case may
        // fall through to the native V3 owner row; all other errors are hard
        // failures and must not silently re-enable the legacy guest path.
        if ((error as { code?: unknown } | undefined)?.code !== 'not_found') throw error;
      }
    }
    let principal: AgentPrincipalRow | undefined;
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `SELECT lark_app_id, open_id, enabled, can_openmemory, execution_mode, created_at, updated_at
           FROM agent_principals WHERE lark_app_id = $1 AND open_id = $2`,
        keyValues(key),
      );
      principal = result.rows[0] ? parsePrincipal(result.rows[0]) : undefined;
    } catch (error) {
      throw toDbError(error);
    }
    if (!principal) throw new AgentPrincipalLookupError('not_found', 'principal is not registered for this Lark app');
    if (!principal.enabled) throw new AgentPrincipalLookupError('disabled', 'principal is disabled');
    if (input.ownerOpenId && input.ownerOpenId !== principal.openId) {
      throw new AgentPrincipalLookupError('disabled', 'session owner does not match the requesting principal');
    }
    return { principal, executionMode: principal.executionMode, principalSkills: await this.getPrincipalSkills(key) };
  }

  /** The only new-instance lookup. Callers must persist its result on Session. */
  async resolveForNewInstance(input: {
    readonly key: AgentPrincipalKey;
    readonly cliId: string;
    readonly ownerOpenId?: string;
    readonly adminOverride?: boolean;
    /** Cold workers must present the topic's frozen stable user identity. */
    readonly sandboxUserId?: string;
  }): Promise<{ principal: AgentPrincipalRow; credential: AgentCredentialRecord; principalBinding: FrozenPrincipalBinding; credentialBinding: FrozenCredentialBinding; credentialSecret: string; principalSkills: readonly FrozenPrincipalSkillBinding[] }> {
    const key = { larkAppId: textKey(input.key.larkAppId, 'larkAppId'), openId: textKey(input.key.openId, 'openId') };
    const [appId, openId] = keyValues(key);
    let result: SqlResult<Record<string, unknown>>;
    try {
      result = await this.db.query<Record<string, unknown>>(
        `SELECT p.lark_app_id, p.open_id, p.enabled, p.can_openmemory, p.execution_mode,
                p.created_at, p.updated_at,
                c.credential_kind, c.base_url, c.model, c.encrypted_secret,
                c.secret_nonce, c.credential_version, c.updated_at AS credential_updated_at,
                (SELECT jsonb_agg(jsonb_build_object(
                    'lark_app_id', s.lark_app_id,
                    'open_id', s.open_id,
                    'skill_name', s.skill_name,
                    'skill_root', s.skill_root,
                    'enabled', s.enabled,
                    'priority', s.priority,
                    'created_at', s.created_at,
                    'updated_at', s.updated_at
                  ) ORDER BY s.priority ASC, s.skill_name ASC)
                   FROM agent_principal_skills s
                  WHERE s.lark_app_id = p.lark_app_id AND s.open_id = p.open_id AND s.enabled = true
                ) AS principal_skills
           FROM agent_principals p
           LEFT JOIN agent_model_credentials c
             ON c.lark_app_id = p.lark_app_id AND c.open_id = p.open_id
          WHERE p.lark_app_id = $1 AND p.open_id = $2`,
        [appId, openId],
      );
    } catch (error) {
      throw toDbError(error);
    }
    const row = result.rows[0];
    if (!row) throw new AgentPrincipalLookupError('not_found', 'principal is not registered for this Lark app');
    const principal = parsePrincipal(row);
    if (!principal.enabled) throw new AgentPrincipalLookupError('disabled', 'principal is disabled');
    if (input.ownerOpenId && input.ownerOpenId !== openId && !input.adminOverride) {
      throw new AgentPrincipalLookupError('disabled', 'session owner does not match the requesting principal');
    }
    if (principal.executionMode !== 'podman') {
      throw new AgentPrincipalLookupError('credential_incompatible', 'native principals do not use Podman credentials');
    }

    if (this.stableRegistry) {
      // A Podman principal must have completed V4 identity migration. The old
      // app/open credential table is intentionally not a new-instance
      // fallback once the stable registry is wired into production.
      let stable: { user: SandboxUserRow; identity: SandboxUserIdentityRow };
      try {
        stable = await this.resolveStableUser(key) as { user: SandboxUserRow; identity: SandboxUserIdentityRow };
      } catch (error) {
        if ((error as { code?: unknown } | undefined)?.code === 'not_found') {
          throw new AgentPrincipalLookupError('not_found', 'sandbox user identity is not registered');
        }
        throw error;
      }
      if (!stable) throw new AgentPrincipalLookupError('not_found', 'sandbox user identity is not registered');
      if (input.sandboxUserId !== undefined && stable.user.sandboxUserId !== input.sandboxUserId) {
        throw new AgentPrincipalLookupError('credential_incompatible', 'cold session sandbox user binding changed');
      }
      if (!stable.user.enabled || !stable.identity.enabled) {
        throw new AgentPrincipalLookupError('disabled', 'sandbox user identity is disabled');
      }
      if (input.ownerOpenId && input.ownerOpenId !== stable.identity.openId && !input.adminOverride) {
        throw new AgentPrincipalLookupError('disabled', 'session owner does not match the requesting principal');
      }
      const harness = AgentPrincipalRepository.harnessForCli(input.cliId);
      let stableCredential: Awaited<ReturnType<NonNullable<StableSandboxUserRegistry>['readSecret']>>;
      try {
        stableCredential = await this.stableRegistry.readSecret({ sandboxUserId: stable.user.sandboxUserId }, harness);
      } catch (error) {
        if ((error as { code?: unknown } | undefined)?.code === 'credential_missing') {
          throw new AgentPrincipalLookupError('credential_missing', 'no compatible model credential is configured');
        }
        throw error;
      }
      if (input.ownerOpenId && input.ownerOpenId !== stable.identity.openId && !input.adminOverride) {
        throw new AgentPrincipalLookupError('disabled', 'session owner does not match the requesting principal');
      }
      try { assertCredentialCompatible(input.cliId, stableCredential.metadata.credentialKind); } catch {
        throw new AgentPrincipalLookupError('credential_incompatible', 'model credential is incompatible with this fixed bot harness');
      }
      const stablePrincipal = AgentPrincipalRepository.principalFromStableUser(stable.user, stable.identity);
      const stableSkills = decodePrincipalSkills(row.principal_skills);
      const principalBinding: FrozenPrincipalBinding = {
        larkAppId: stable.identity.larkAppId,
        openId: stable.identity.openId,
        enabled: true,
        canOpenMemory: stablePrincipal.canOpenMemory,
        cliId: input.cliId as PodmanCliId,
        credentialVersion: stableCredential.metadata.credentialVersion,
        credentialKind: stableCredential.metadata.credentialKind,
        sandboxUserId: stable.user.sandboxUserId,
        podGeneration: stable.user.podGeneration,
        ...(input.ownerOpenId ? { ownerOpenId: input.ownerOpenId } : {}),
        ...(stableSkills.length > 0 ? { skills: stableSkills } : {}),
      };
      const credentialBinding: FrozenCredentialBinding = {
        kind: stableCredential.metadata.credentialKind,
        credentialVersion: stableCredential.metadata.credentialVersion,
        ...(stableCredential.metadata.baseUrl ? { baseUrl: stableCredential.metadata.baseUrl } : {}),
        ...(stableCredential.metadata.model ? { model: stableCredential.metadata.model } : {}),
      };
      const credential: AgentCredentialRecord = {
        larkAppId: key.larkAppId,
        openId: key.openId,
        credentialKind: stableCredential.metadata.credentialKind,
        ...(stableCredential.metadata.baseUrl ? { baseUrl: stableCredential.metadata.baseUrl } : {}),
        ...(stableCredential.metadata.model ? { model: stableCredential.metadata.model } : {}),
        credentialVersion: stableCredential.metadata.credentialVersion,
        updatedAt: stableCredential.metadata.updatedAt,
        // Stable credentials are decrypted only by the registry. These empty
        // buffers preserve the old return shape without leaking/copying the
        // ciphertext into Session or a dashboard response.
        encryptedSecret: Buffer.alloc(0),
        secretNonce: Buffer.alloc(0),
      };
      return {
        principal: stablePrincipal,
        credential,
        principalBinding,
        credentialBinding,
        credentialSecret: stableCredential.secret,
        principalSkills: stableSkills,
      };
    }
    const principalSkills = decodePrincipalSkills(row.principal_skills);
    if (!row.credential_kind || row.encrypted_secret === undefined || row.secret_nonce === undefined) {
      throw new AgentPrincipalLookupError('credential_missing', 'no compatible model credential is configured');
    }
    const credential = parseCredential({
      ...row,
      updated_at: row.credential_updated_at,
    });
    try { assertCredentialCompatible(input.cliId, credential.credentialKind); } catch {
      throw new AgentPrincipalLookupError('credential_incompatible', 'model credential is incompatible with this fixed bot harness');
    }
    if (!this.masterKey) throw new AgentPrincipalLookupError('database_unavailable', 'credential master key is not configured');
    const credentialSecret = decryptCredentialUtf8(
      { ciphertext: credential.encryptedSecret, nonce: credential.secretNonce },
      this.masterKey,
      key,
    );
    const principalBinding: FrozenPrincipalBinding = {
      ...key,
      enabled: true,
      canOpenMemory: principal.canOpenMemory,
      cliId: input.cliId as PodmanCliId,
      credentialVersion: credential.credentialVersion,
      credentialKind: credential.credentialKind,
      ...(input.ownerOpenId ? { ownerOpenId: input.ownerOpenId } : {}),
      ...(principalSkills.length > 0 ? { skills: principalSkills } : {}),
    };
    const credentialBinding: FrozenCredentialBinding = {
      kind: credential.credentialKind,
      credentialVersion: credential.credentialVersion,
      ...(credential.baseUrl ? { baseUrl: credential.baseUrl } : {}),
      ...(credential.model ? { model: credential.model } : {}),
    };
    return { principal, credential, principalBinding, credentialBinding, credentialSecret, principalSkills };
  }

  async upsertPrincipal(input: {
    readonly key: AgentPrincipalKey;
    readonly enabled?: boolean;
    readonly canOpenMemory?: boolean;
    readonly executionMode?: AgentExecutionMode;
  }): Promise<AgentPrincipalRow> {
    const [appId, openId] = keyValues(input.key);
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `INSERT INTO agent_principals (lark_app_id, open_id, enabled, can_openmemory, execution_mode)
         VALUES ($1, $2, COALESCE($3, true), COALESCE($4, false), COALESCE($5, 'podman'))
         ON CONFLICT (lark_app_id, open_id) DO UPDATE SET
           enabled = COALESCE($3, agent_principals.enabled),
           can_openmemory = COALESCE($4, agent_principals.can_openmemory),
           execution_mode = COALESCE($5, agent_principals.execution_mode),
           updated_at = now()
         RETURNING lark_app_id, open_id, enabled, can_openmemory, execution_mode, created_at, updated_at`,
        [appId, openId, input.enabled ?? null, input.canOpenMemory ?? null, input.executionMode ?? null],
      );
      const principal = parsePrincipal(result.rows[0]!);
      await ensureDefaultPrincipalSkillRows(this.db, input.key);
      return principal;
    } catch (error) {
      throw toDbError(error);
    }
  }

  async setPrincipalEnabled(key: AgentPrincipalKey, enabled: boolean): Promise<AgentPrincipalRow | undefined> {
    const [appId, openId] = keyValues(key);
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `UPDATE agent_principals SET enabled = $3, updated_at = now()
          WHERE lark_app_id = $1 AND open_id = $2
          RETURNING lark_app_id, open_id, enabled, can_openmemory, execution_mode, created_at, updated_at`,
        [appId, openId, enabled],
      );
      return result.rows[0] ? parsePrincipal(result.rows[0]) : undefined;
    } catch (error) {
      throw toDbError(error);
    }
  }

  async setOpenMemory(key: AgentPrincipalKey, canOpenMemory: boolean): Promise<AgentPrincipalRow | undefined> {
    const [appId, openId] = keyValues(key);
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `UPDATE agent_principals SET can_openmemory = $3, updated_at = now()
          WHERE lark_app_id = $1 AND open_id = $2
          RETURNING lark_app_id, open_id, enabled, can_openmemory, execution_mode, created_at, updated_at`,
        [appId, openId, canOpenMemory],
      );
      return result.rows[0] ? parsePrincipal(result.rows[0]) : undefined;
    } catch (error) {
      throw toDbError(error);
    }
  }

  async setExecutionMode(key: AgentPrincipalKey, executionMode: AgentExecutionMode): Promise<AgentPrincipalRow | undefined> {
    const [appId, openId] = keyValues(key);
    if (executionMode !== 'native' && executionMode !== 'podman') throw new TypeError('invalid execution mode');
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `UPDATE agent_principals SET execution_mode = $3, updated_at = now()
          WHERE lark_app_id = $1 AND open_id = $2
          RETURNING lark_app_id, open_id, enabled, can_openmemory, execution_mode, created_at, updated_at`,
        [appId, openId, executionMode],
      );
      return result.rows[0] ? parsePrincipal(result.rows[0]) : undefined;
    } catch (error) {
      throw toDbError(error);
    }
  }

  async putCredential(input: {
    readonly key: AgentPrincipalKey;
    readonly credentialKind: PodmanCredentialKind;
    /** V4 stable harness. Omitted by legacy callers; ChatGPT is inferred. */
    readonly harness?: SandboxUserHarness;
    readonly secret: string | Buffer;
    readonly baseUrl?: string;
    readonly model?: string;
    readonly expectedVersion?: number;
  }): Promise<AgentCredentialMetadata> {
    const key = { larkAppId: textKey(input.key.larkAppId, 'larkAppId'), openId: textKey(input.key.openId, 'openId') };
    const [appId, openId] = keyValues(key);
    if (!this.masterKey) throw new Error('credential master key is not configured');
    if (input.credentialKind === 'api') {
      validateApiCredentialInput({ baseUrl: input.baseUrl ?? '', model: input.model ?? '', key: typeof input.secret === 'string' ? input.secret : input.secret.toString('utf8') });
    } else if (input.baseUrl !== undefined || input.model !== undefined) {
      throw new TypeError('Codex ChatGPT credentials do not accept BaseURL or model');
    }
    if (this.stableRegistry) {
      const stable = await this.resolveStableUser(key);
      if (!stable) throw new AgentPrincipalLookupError('not_found', 'sandbox user identity is not registered');
      const harness = input.harness ?? (input.credentialKind === 'codex_chatgpt' ? 'codex' : undefined);
      if (!harness) throw new AgentPrincipalLookupError('credential_incompatible', 'API credential write requires an explicit harness');
      const metadata = await this.stableRegistry.putCredential({
        user: { sandboxUserId: stable.user.sandboxUserId },
        harness,
        credentialKind: input.credentialKind,
        secret: input.secret,
        ...(input.baseUrl !== undefined ? { baseUrl: input.baseUrl } : {}),
        ...(input.model !== undefined ? { model: input.model } : {}),
        ...(input.expectedVersion !== undefined ? { expectedVersion: input.expectedVersion } : {}),
      });
      return {
        larkAppId: key.larkAppId,
        openId: key.openId,
        credentialKind: metadata.credentialKind,
        ...(metadata.baseUrl ? { baseUrl: metadata.baseUrl } : {}),
        ...(metadata.model ? { model: metadata.model } : {}),
        credentialVersion: metadata.credentialVersion,
        updatedAt: metadata.updatedAt,
        keyFingerprint: metadata.keyFingerprint,
      };
    }
    const encrypted = encryptCredential(input.secret, this.masterKey, key);
    let client: SqlTransaction;
    try {
      client = await this.db.connect();
    } catch (error) {
      throw toDbError(error);
    }
    try {
      await client.query('BEGIN');
      // Lock the parent row before reading the optional credential row. A
      // missing child row has no lock of its own, so two first writers would
      // otherwise both observe version 0 and race through the INSERT.
      await this.requireEnabled(client, key, true);
      const current = await client.query<Record<string, unknown>>(
        `SELECT credential_version FROM agent_model_credentials
          WHERE lark_app_id = $1 AND open_id = $2 FOR UPDATE`, [appId, openId],
      );
      const actual = current.rows[0] ? Number(current.rows[0].credential_version) : undefined;
      // Version zero is the explicit create-if-absent sentinel.  Treat a
      // missing row as version 0 so two first writers cannot both win.
      if (input.expectedVersion !== undefined && (actual ?? 0) !== input.expectedVersion) {
        throw new CredentialVersionConflictError(input.expectedVersion, actual);
      }
      const nextVersion = actual === undefined ? 1 : actual + 1;
      const result = await client.query<Record<string, unknown>>(
        `INSERT INTO agent_model_credentials
           (lark_app_id, open_id, credential_kind, base_url, model, encrypted_secret, secret_nonce, credential_version)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (lark_app_id, open_id) DO UPDATE SET
           credential_kind = EXCLUDED.credential_kind,
           base_url = EXCLUDED.base_url,
           model = EXCLUDED.model,
           encrypted_secret = EXCLUDED.encrypted_secret,
           secret_nonce = EXCLUDED.secret_nonce,
           credential_version = EXCLUDED.credential_version,
           updated_at = now()
         RETURNING lark_app_id, open_id, credential_kind, base_url, model, credential_version, updated_at`,
        [appId, openId, input.credentialKind, input.baseUrl ?? null, input.model ?? null, encrypted.ciphertext, encrypted.nonce, nextVersion],
      );
      await client.query('COMMIT');
      const row = result.rows[0]!;
      const legacyMetadata: AgentCredentialMetadata = {
        larkAppId: String(row.lark_app_id), openId: String(row.open_id),
        credentialKind: String(row.credential_kind) as PodmanCredentialKind,
        ...(typeof row.base_url === 'string' ? { baseUrl: row.base_url } : {}),
        ...(typeof row.model === 'string' ? { model: row.model } : {}),
        credentialVersion: Number(row.credential_version), updatedAt: dateValue(row.updated_at),
        keyFingerprint: credentialFingerprint(input.secret),
      };
      return legacyMetadata;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      if (error instanceof CredentialVersionConflictError) throw error;
      throw toDbError(error);
    } finally {
      client.release();
    }
  }

  async readSecret(key: AgentPrincipalKey, expectedVersion?: number, harnessInput?: SandboxUserHarness): Promise<{ metadata: AgentCredentialMetadata; secret: string }> {
    if (!this.masterKey) throw new Error('credential master key is not configured');
    if (this.stableRegistry) {
      try {
        const stable = await this.resolveStableUser(key);
        if (stable) {
          // A refresh/read caller must provide its fixed harness. Blindly
          // scanning four slots can select a same-version credential belonging
          // to a different CLI and inject the wrong provider.
          const harnesses: readonly SandboxUserHarness[] = harnessInput
            ? [harnessInput]
            : ['codex'];
          for (const harness of harnesses) {
            try {
              const result = await this.stableRegistry.readSecret(
                { sandboxUserId: stable.user.sandboxUserId }, harness, expectedVersion,
              );
              return {
                metadata: {
                  larkAppId: key.larkAppId,
                  openId: key.openId,
                  credentialKind: result.metadata.credentialKind,
                  ...(result.metadata.baseUrl ? { baseUrl: result.metadata.baseUrl } : {}),
                  ...(result.metadata.model ? { model: result.metadata.model } : {}),
                  credentialVersion: result.metadata.credentialVersion,
                  updatedAt: result.metadata.updatedAt,
                  keyFingerprint: result.metadata.keyFingerprint,
                },
                secret: result.secret,
              };
            } catch (error) {
              if ((error as { code?: unknown } | undefined)?.code === 'credential_missing') continue;
              if (error instanceof CredentialVersionConflictError) continue;
              throw error;
            }
          }
          throw new AgentPrincipalLookupError('credential_missing', 'credential is not configured');
        }
      } catch (error) {
        if ((error as { code?: unknown } | undefined)?.code !== 'not_found') throw error;
      }
    }
    await this.requireEnabled(this.db, key);
    const record = await this.getCredential(key);
    if (!record) throw new AgentPrincipalLookupError('credential_missing', 'credential is not configured');
    if (expectedVersion !== undefined && record.credentialVersion !== expectedVersion) {
      throw new CredentialVersionConflictError(expectedVersion, record.credentialVersion);
    }
    const secret = decryptCredentialUtf8(
      { ciphertext: record.encryptedSecret, nonce: record.secretNonce },
      this.masterKey,
      key,
    );
    const { encryptedSecret: _encrypted, secretNonce: _nonce, ...metadata } = record;
    return { metadata, secret };
  }

  async deleteCredential(key: AgentPrincipalKey, expectedVersion?: number, credentialKind?: PodmanCredentialKind, harnessInput?: SandboxUserHarness): Promise<boolean> {
    const [appId, openId] = keyValues(key);
    const values: unknown[] = [appId, openId];
    const clauses: string[] = [];
    if (expectedVersion !== undefined) {
      values.push(expectedVersion);
      clauses.push(`credential_version = $${values.length}`);
    }
    if (credentialKind !== undefined) {
      values.push(credentialKind);
      clauses.push(`credential_kind = $${values.length}`);
    }
    const guard = clauses.length > 0 ? ` AND ${clauses.join(' AND ')}` : '';
    try {
      await this.requireEnabled(this.db, key);
      if (this.stableRegistry) {
        let stable: { user: SandboxUserRow; identity: SandboxUserIdentityRow } | undefined;
        try {
          stable = await this.resolveStableUser(key);
        } catch (error) {
          if ((error as { code?: unknown } | undefined)?.code !== 'not_found') throw error;
        }
        if (stable) {
          const harness = harnessInput ?? (credentialKind === 'codex_chatgpt' || credentialKind === undefined ? 'codex' : undefined);
          if (!harness) throw new AgentPrincipalLookupError('credential_incompatible', 'API credential deletion requires an explicit harness');
          return await this.stableRegistry.deleteCredential(
            { sandboxUserId: stable.user.sandboxUserId }, harness, expectedVersion,
          );
        }
      }
      const result = await this.db.query(
        `DELETE FROM agent_model_credentials WHERE lark_app_id = $1 AND open_id = $2${guard}`,
        values,
      );
      if (expectedVersion !== undefined && Number(result.rowCount ?? 0) === 0) {
        const current = await this.getCredential(key);
        if (current && (credentialKind === undefined || current.credentialKind === credentialKind)) {
          throw new CredentialVersionConflictError(expectedVersion, current.credentialVersion);
        }
      }
      return Number(result.rowCount ?? 0) > 0;
    } catch (error) {
      if (error instanceof CredentialVersionConflictError) throw error;
      throw toDbError(error);
    }
  }

  async seedPrincipals(rows: ReadonlyArray<{ key: AgentPrincipalKey; canOpenMemory?: boolean; enabled?: boolean; executionMode?: AgentExecutionMode }>): Promise<AgentPrincipalRow[]> {
    let client: SqlTransaction;
    try {
      client = await this.db.connect();
    } catch (error) {
      throw toDbError(error);
    }
    try {
      await client.query('BEGIN');
      const result: AgentPrincipalRow[] = [];
      for (const row of rows) {
        const [appId, openId] = keyValues(row.key);
        const upserted = await client.query<Record<string, unknown>>(
        `INSERT INTO agent_principals (lark_app_id, open_id, enabled, can_openmemory, execution_mode)
           VALUES ($1, $2, COALESCE($3, true), COALESCE($4, false), COALESCE($5, 'podman'))
           ON CONFLICT (lark_app_id, open_id) DO UPDATE SET
             enabled = COALESCE($3, agent_principals.enabled),
             can_openmemory = COALESCE($4, agent_principals.can_openmemory),
             execution_mode = COALESCE($5, agent_principals.execution_mode),
             updated_at = now()
           RETURNING lark_app_id, open_id, enabled, can_openmemory, execution_mode, created_at, updated_at`,
          [appId, openId, row.enabled ?? null, row.canOpenMemory ?? null, row.executionMode ?? null],
        );
        result.push(parsePrincipal(upserted.rows[0]!));
      }
      await client.query('COMMIT');
      for (const row of rows) await ensureDefaultPrincipalSkillRows(this.db, row.key);
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw toDbError(error);
    } finally {
      client.release();
    }
  }

  async beginCodexLoginTask(input: { key: AgentPrincipalKey; taskId: string; leaseExpiresAt: Date }): Promise<void> {
    const [appId, openId] = keyValues(input.key);
    try {
      await withAgentPrincipalTransaction(this.db, async tx => {
      await this.requireEnabled(tx, input.key);
      // Expired rows are coordination history, not active leases. Reaping
      // them here lets a principal start a new login without requiring a
      // separate status poll first.
      await tx.query(
        `UPDATE agent_codex_login_tasks SET status = 'expired', error_code = 'device_auth_expired', updated_at = now()
          WHERE lark_app_id = $1 AND open_id = $2 AND status = 'pending' AND lease_expires_at <= now()`,
        [appId, openId],
      );
      const inserted = await tx.query(
        `INSERT INTO agent_codex_login_tasks (task_id, lark_app_id, open_id, status, lease_expires_at)
         VALUES ($1::uuid, $2, $3, 'pending', $4)
         ON CONFLICT (lark_app_id, open_id) WHERE status = 'pending'
         DO NOTHING
         RETURNING task_id`,
        [input.taskId, appId, openId, input.leaseExpiresAt],
      );
      if (Number(inserted.rowCount ?? inserted.rows.length) === 0) throw new CodexLoginTaskConflictError();
      });
    } catch (error) {
      if (error instanceof CodexLoginTaskConflictError) throw error;
      throw toDbError(error);
    }
  }

  private async requireEnabled(db: SqlExecutor, key: AgentPrincipalKey, forUpdate = false): Promise<void> {
    const [appId, openId] = keyValues(key);
    let result: SqlResult<Record<string, unknown>>;
    try {
      result = await db.query<Record<string, unknown>>(
        `SELECT enabled FROM agent_principals WHERE lark_app_id = $1 AND open_id = $2${forUpdate ? ' FOR UPDATE' : ''}`,
        [appId, openId],
      );
    } catch (error) {
      throw toDbError(error);
    }
    if (!result.rows[0]) throw new AgentPrincipalLookupError('not_found', 'principal is not registered for this Lark app');
    if (!boolValue(result.rows[0].enabled)) throw new AgentPrincipalLookupError('disabled', 'principal is disabled');
  }

  async updateCodexLoginTask(taskId: string, input: { status: 'pending' | 'ready' | 'failed' | 'logged_out' | 'expired'; verificationUri?: string; userCode?: string; errorCode?: string }): Promise<void> {
    try {
      await this.db.query(
        `UPDATE agent_codex_login_tasks SET status = $2, verification_uri = $3,
           user_code = $4, error_code = $5, updated_at = now() WHERE task_id = $1::uuid`,
        [taskId, input.status, input.verificationUri ?? null, input.userCode ?? null, input.errorCode ?? null],
      );
    } catch (error) {
      throw toDbError(error);
    }
  }

  async getCodexLoginTask(key: AgentPrincipalKey): Promise<AgentCodexLoginTaskRecord | undefined> {
    const [appId, openId] = keyValues(key);
    try {
      const result = await this.db.query<Record<string, unknown>>(
        `SELECT task_id, lark_app_id, open_id, status, lease_expires_at,
                verification_uri, user_code, error_code
           FROM agent_codex_login_tasks
          WHERE lark_app_id = $1 AND open_id = $2
          ORDER BY created_at DESC LIMIT 1`,
        [appId, openId],
      );
      return result.rows[0] ? parseLoginTask(result.rows[0]) : undefined;
    } catch (error) {
      throw toDbError(error);
    }
  }
}

/**
 * BOTMUX_AGENT_DATABASE_URL is an explicit override for deployments that keep
 * identity/credentials in a separate Postgres database. In the default
 * install, QRANT_RESEARCH_DATABASE_URL points at the same research DB used by
 * the T3 lake bridge, so both services share the principal tables. Keeping the
 * precedence explicit prevents an accidental test/local override from being
 * silently ignored.
 */
export function resolveAgentPrincipalDatabaseUrl(env: NodeJS.ProcessEnv = process.env): string | undefined {
  return env.BOTMUX_AGENT_DATABASE_URL?.trim() || env.QRANT_RESEARCH_DATABASE_URL?.trim();
}

/** Production factory is optional so unit tests can use a tiny fake executor. */
export function createAgentPrincipalPool(connectionString = resolveAgentPrincipalDatabaseUrl()): SqlPool {
  if (!connectionString?.trim()) throw new AgentPrincipalLookupError('database_unavailable', 'agent principal database is not configured');
  const require = createRequire(import.meta.url);
  let pg: any;
  try { pg = require('pg'); } catch { throw new AgentPrincipalLookupError('database_unavailable', 'the pg package is not installed'); }
  return new pg.Pool({ connectionString, max: 4, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 5_000 }) as SqlPool;
}
