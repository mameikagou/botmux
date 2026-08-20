import { describe, expect, it } from 'vitest';
import {
  decryptSandboxUserCredentialUtf8,
  encryptSandboxUserCredential,
} from '../src/services/agent-principal-crypto.js';
import {
  SANDBOX_USER_REGISTRY_DOWN_SQL,
  SANDBOX_USER_REGISTRY_UP_SQL,
  SandboxUserRegistryRepository,
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
});

/** Small SQL contract double: it intentionally stores no secret values. */
class ScriptedPool implements SqlPool {
  readonly secretLikeValues: unknown[] = [];
  constructor(private readonly state: {
    readonly user: SandboxUserRow;
    readonly identity: Record<string, unknown>;
    readonly rows: Record<string, unknown>[];
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
      return { rows: [{
        sandbox_user_id: this.state.user.sandboxUserId,
        enabled: this.state.user.enabled,
        can_openmemory: this.state.user.canOpenMemory,
        execution_mode: this.state.user.executionMode,
        created_at: this.state.user.createdAt,
        updated_at: this.state.user.updatedAt,
      }] as Row[] };
    }
    if (text.includes('INSERT INTO sandbox_user_identities')) {
      return { rows: [this.state.identity] as Row[] };
    }
    return { rows: [] as Row[], rowCount: 0 };
  }
}
