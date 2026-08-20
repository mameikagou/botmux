import { describe, expect, it } from 'vitest';
import {
  decryptSandboxUserCredentialUtf8,
  encryptSandboxUserCredential,
} from '../src/services/agent-principal-crypto.js';
import {
  SANDBOX_USER_REGISTRY_DOWN_SQL,
  SANDBOX_USER_REGISTRY_UP_SQL,
  SandboxUserRegistryRepository,
  applySandboxUserRegistryMigration,
  type SandboxUserRow,
} from '../src/services/sandbox-user-registry.js';
import type { SqlPool, SqlResult, SqlTransaction } from '../src/services/agent-principal-store.js';

describe('v4 sandbox user registry', () => {
  it('binds credential ciphertext to user, harness, metadata and CAS version', () => {
    const key = Buffer.alloc(32, 0x37);
    const aad = {
      sandboxUserId: 'user-a',
      harness: 'claude-code',
      baseUrl: 'https://api.example.test',
      model: 'model-a',
      credentialVersion: 1,
    } as const;
    const encrypted = encryptSandboxUserCredential('secret-a', key, aad);
    expect(decryptSandboxUserCredentialUtf8(encrypted, key, aad)).toBe('secret-a');
    expect(() => decryptSandboxUserCredentialUtf8(encrypted, key, { ...aad, harness: 'pi' })).toThrow(/authentication failed/);
    expect(() => decryptSandboxUserCredentialUtf8(encrypted, key, { ...aad, model: 'model-b' })).toThrow(/authentication failed/);
    expect(() => decryptSandboxUserCredentialUtf8(encrypted, key, { ...aad, credentialVersion: 2 })).toThrow(/authentication failed/);
  });

  it('publishes additive, non-secret registry tables and teardown order', () => {
    expect(SANDBOX_USER_REGISTRY_UP_SQL).toContain('CREATE TABLE IF NOT EXISTS sandbox_users');
    expect(SANDBOX_USER_REGISTRY_UP_SQL).toContain('CREATE TABLE IF NOT EXISTS sandbox_user_identities');
    expect(SANDBOX_USER_REGISTRY_UP_SQL).toContain('CREATE TABLE IF NOT EXISTS sandbox_user_credentials');
    expect(SANDBOX_USER_REGISTRY_UP_SQL).toContain('CREATE TABLE IF NOT EXISTS sandbox_pod_runtime_manifests');
    expect(SANDBOX_USER_REGISTRY_UP_SQL).toContain("harness IN ('codex', 'claude-code', 'pi', 'opencode')");
    expect(SANDBOX_USER_REGISTRY_UP_SQL).toContain('encrypted_secret bytea NOT NULL');
    expect(SANDBOX_USER_REGISTRY_UP_SQL).toContain('credential_version bigint');
    expect(SANDBOX_USER_REGISTRY_DOWN_SQL.indexOf('sandbox_pod_runtime_manifests'))
      .toBeLessThan(SANDBOX_USER_REGISTRY_DOWN_SQL.indexOf('sandbox_users'));
    expect(SANDBOX_USER_REGISTRY_UP_SQL).not.toMatch(/secret[^\n]*text/iu);
  });

  it('uses one stable user id for a repeated identity bind', async () => {
    const user: SandboxUserRow = {
      sandboxUserId: 'user-a', enabled: true, canOpenMemory: false, executionMode: 'podman',
      podGeneration: 1,
      createdAt: '2026-08-20T00:00:00.000Z', updatedAt: '2026-08-20T00:00:00.000Z',
    };
    const identity = {
      sandbox_user_id: 'user-a', lark_app_id: 'app-a', open_id: 'open-a', enabled: true,
      created_at: user.createdAt, updated_at: user.updatedAt,
    };
    const rows: Record<string, unknown>[] = [];
    const pool = new ScriptedPool({ user, identity, rows });
    const repository = new SandboxUserRegistryRepository(pool, Buffer.alloc(32, 0x44));
    const first = await repository.bindIdentity({ key: { larkAppId: 'app-a', openId: 'open-a' }, sandboxUserId: 'user-a' });
    const second = await repository.bindIdentity({ key: { larkAppId: 'app-a', openId: 'open-a' } });
    expect(first.user.sandboxUserId).toBe('user-a');
    expect(second.user.sandboxUserId).toBe('user-a');
    expect(pool.secretLikeValues).toHaveLength(0);
  });

  it('preserves runtime pod generations across 2 -> 3 state transitions', async () => {
    const pool = new RuntimePool();
    const repository = new SandboxUserRegistryRepository(pool, Buffer.alloc(32, 0x44));
    const runtime = await repository.createRuntime({
      sandboxUserId: 'user-a', sessionId: 'session-a', podGeneration: 2,
      harness: 'claude-code', imageDigest: 'localhost/botmux:test@sha256:' + 'a'.repeat(64),
    });
    expect(pool.lastInsertSql).toContain("'runtimeId', $1::text");
    expect(pool.lastInsertSql).toContain("'podGeneration', $4::bigint");
    expect(runtime.podGeneration).toBe(2);
    const running = await repository.updateRuntimeState({
      runtimeId: runtime.runtimeId, state: 'running', expectedState: 'provisioning',
    });
    expect(running.podGeneration).toBe(2);
    const stopped = await repository.updateRuntimeState({
      runtimeId: runtime.runtimeId, state: 'stopped', expectedState: 'running',
    });
    expect(stopped.podGeneration).toBe(2);

    const replacement = await repository.createRuntime({
      sandboxUserId: 'user-a', sessionId: 'session-b', podGeneration: 3,
      harness: 'claude-code', imageDigest: 'localhost/botmux:test@sha256:' + 'b'.repeat(64),
    });
    expect((await repository.updateRuntimeState({
      runtimeId: replacement.runtimeId, state: 'running', expectedState: 'provisioning',
    })).podGeneration).toBe(3);
  });

  it('rejects rows whose pod generation is missing instead of defaulting to 1', async () => {
    const user: SandboxUserRow = {
      sandboxUserId: 'user-missing-generation', enabled: true, canOpenMemory: false, executionMode: 'podman',
      podGeneration: 1,
      createdAt: '2026-08-20T00:00:00.000Z', updatedAt: '2026-08-20T00:00:00.000Z',
    };
    const pool = new ScriptedPool({
      user,
      identity: { sandbox_user_id: user.sandboxUserId, lark_app_id: 'app', open_id: 'open', enabled: true },
      rows: [],
      omitGeneration: true,
    });
    const repository = new SandboxUserRegistryRepository(pool, Buffer.alloc(32, 0x44));
    await expect(repository.createUser({ sandboxUserId: user.sandboxUserId }))
      .rejects.toMatchObject({ code: 'database_unavailable' });
  });

  it('serializes additive DDL behind the shared advisory migration lock', async () => {
    const statements: string[] = [];
    const pool: SqlPool = {
      query: async <Row = Record<string, unknown>>(text: string): Promise<SqlResult<Row>> => {
        statements.push(text);
        return { rows: [] as Row[] };
      },
      connect: async () => ({
        query: async <Row = Record<string, unknown>>(text: string): Promise<SqlResult<Row>> => {
          statements.push(text);
          return { rows: [] as Row[] };
        },
        release: () => undefined,
      }),
    };
    await applySandboxUserRegistryMigration(pool);
    expect(statements[1]).toContain('pg_advisory_xact_lock');
    expect(statements[2]).toContain('CREATE TABLE IF NOT EXISTS sandbox_users');
    expect(SANDBOX_USER_REGISTRY_UP_SQL).toContain('pod_generation bigint');
  });
});

/** Small SQL contract double: it intentionally stores no secret values. */
class ScriptedPool implements SqlPool {
  readonly secretLikeValues: unknown[] = [];
  constructor(private readonly state: {
    readonly user: SandboxUserRow;
    readonly identity: Record<string, unknown>;
    readonly rows: Record<string, unknown>[];
    readonly omitGeneration?: boolean;
  }) {}

  async connect(): Promise<SqlTransaction> {
    return {
      query: async <Row = Record<string, unknown>>(text: string, values: readonly unknown[] = []): Promise<SqlResult<Row>> => {
        if (text === 'BEGIN' || text === 'COMMIT' || text === 'ROLLBACK') return { rows: [] as Row[] };
        return this.query<Row>(text, values);
      },
      release: () => undefined,
    };
  }

  async query<Row = Record<string, unknown>>(text: string, values: readonly unknown[] = []): Promise<SqlResult<Row>> {
    for (const value of values) {
      if (typeof value === 'string' && /secret|token|key/iu.test(value)) this.secretLikeValues.push(value);
      if (Buffer.isBuffer(value)) this.secretLikeValues.push(value);
    }
    if (text.includes('SELECT sandbox_user_id FROM sandbox_user_identities')) {
      return { rows: [this.state.identity] as Row[] };
    }
    if (text.includes('INSERT INTO sandbox_users')) {
      const row: Record<string, unknown> = {
        sandbox_user_id: this.state.user.sandboxUserId,
        enabled: this.state.user.enabled,
        can_openmemory: this.state.user.canOpenMemory,
        execution_mode: this.state.user.executionMode,
        pod_generation: this.state.user.podGeneration,
        created_at: this.state.user.createdAt,
        updated_at: this.state.user.updatedAt,
      };
      if (this.state.omitGeneration) delete row.pod_generation;
      return { rows: [row] as Row[] };
    }
    if (text.includes('INSERT INTO sandbox_user_identities')) {
      return { rows: [this.state.identity] as Row[] };
    }
    return { rows: [] as Row[], rowCount: 0 };
  }
}

class RuntimePool implements SqlPool {
  private row: Record<string, unknown> | undefined;
  lastInsertSql = '';

  async connect(): Promise<SqlTransaction> {
    return {
      query: async <Row = Record<string, unknown>>(text: string, values: readonly unknown[] = []) => {
        if (text === 'BEGIN' || text === 'COMMIT' || text === 'ROLLBACK') return { rows: [] as Row[] };
        return this.query<Row>(text, values);
      },
      release: () => undefined,
    };
  }

  async query<Row = Record<string, unknown>>(text: string, values: readonly unknown[] = []): Promise<SqlResult<Row>> {
    if (text.includes('INSERT INTO sandbox_pod_runtime_manifests')) {
      this.lastInsertSql = text;
      const now = '2026-08-20T00:00:00.000Z';
      this.row = {
        runtime_id: values[0], sandbox_user_id: values[1], session_id: values[2], pod_generation: values[3],
        harness: values[4], state: 'provisioning', image_digest: values[5], container_name: values[6],
        workspace_path: values[7], home_path: values[8], credential_version: values[9], source_repo: values[10],
        source_branch: values[11], created_at: now, updated_at: now, stopped_at: null, failure_code: null,
      };
      return { rows: [this.row] as Row[] };
    }
    if (text.includes('SELECT runtime_id, sandbox_user_id')) {
      return { rows: this.row ? [this.row as Row] : [] };
    }
    if (text.includes('UPDATE sandbox_pod_runtime_manifests')) {
      if (!this.row) return { rows: [] as Row[], rowCount: 0 };
      const state = String(values[1]);
      this.row.state = state;
      this.row.failure_code = values[2] ?? null;
      this.row.stopped_at = state === 'stopped' || state === 'failed' ? (this.row.stopped_at ?? '2026-08-20T00:00:01.000Z') : null;
      this.row.updated_at = '2026-08-20T00:00:01.000Z';
      return { rows: [this.row as Row], rowCount: 1 };
    }
    throw new Error(`unexpected runtime query ${text}`);
  }
}
