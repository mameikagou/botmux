import { afterAll, describe, expect, it } from 'vitest';
import {
  AgentPrincipalRepository,
  applyAgentPrincipalMigration,
  createAgentPrincipalPool,
  rollbackAgentPrincipalMigration,
} from '../src/services/agent-principal-store.js';
import {
  SandboxUserRegistryRepository,
  applySandboxUserRegistryMigration,
  rollbackSandboxUserRegistryMigration,
} from '../src/services/sandbox-user-registry.js';

const enabled = process.env.BOTMUX_T6_PG_INTEGRATION === '1'
  && typeof process.env.BOTMUX_AGENT_DATABASE_URL === 'string'
  && process.env.BOTMUX_AGENT_DATABASE_URL.trim().length > 0;

describe.skipIf(!enabled)('v4 sandbox user registry PostgreSQL integration', () => {
  const pool = enabled ? createAgentPrincipalPool(process.env.BOTMUX_AGENT_DATABASE_URL) : undefined;
  const masterKey = Buffer.alloc(32, 0x6b);
  const legacy = { larkAppId: `v4_legacy_${process.pid}`, openId: 'ou_v4_legacy' };
  const userId = `v4_user_${process.pid}`;
  const old = pool ? new AgentPrincipalRepository(pool, masterKey) : undefined;
  const registry = pool ? new SandboxUserRegistryRepository(pool, masterKey) : undefined;

  afterAll(async () => {
    if (!pool) return;
    await rollbackSandboxUserRegistryMigration(pool).catch(() => undefined);
    await rollbackAgentPrincipalMigration(pool).catch(() => undefined);
    await pool.end?.();
  });

  it('migrates a v3 app/open credential into a stable per-harness user record', async () => {
    if (!pool || !old || !registry) return;
    await applyAgentPrincipalMigration(pool);
    await applySandboxUserRegistryMigration(pool);
    await old.seedPrincipals([{ key: legacy, canOpenMemory: false, executionMode: 'podman' }]);
    await old.putCredential({
      key: legacy,
      credentialKind: 'api',
      secret: 'v4-disposable-secret',
      baseUrl: 'https://api.example.test',
      model: 'v4-model',
    });
    const migrated = await registry.migrateLegacyPrincipal({ key: legacy, harness: 'claude-code', sandboxUserId: userId });
    expect(migrated.user.sandboxUserId).toBe(userId);
    expect(migrated.identity.openId).toBe(legacy.openId);
    expect(migrated.migratedCredential).toBe(true);
    const resolved = await registry.resolveUserForIdentity(legacy);
    expect(resolved.user.sandboxUserId).toBe(userId);
    const credential = await registry.readSecret({ sandboxUserId: userId }, 'claude-code');
    expect(credential.secret).toBe('v4-disposable-secret');
    expect(credential.metadata.baseUrl).toBe('https://api.example.test');
    expect(credential.metadata.model).toBe('v4-model');
  });

  it('retains a stopped runtime manifest for cold-start recovery and fences state races', async () => {
    if (!registry) return;
    const runtime = await registry.createRuntime({
      sandboxUserId: userId,
      sessionId: `v4_session_${process.pid}`,
      podGeneration: 1,
      harness: 'claude-code',
      imageDigest: 'localhost/botmux:test@sha256:' + 'a'.repeat(64),
      credentialVersion: 1,
    });
    expect(runtime.state).toBe('provisioning');
    const running = await registry.updateRuntimeState({ runtimeId: runtime.runtimeId, state: 'running', expectedState: 'provisioning' });
    expect(running.state).toBe('running');
    const stopped = await registry.updateRuntimeState({ runtimeId: runtime.runtimeId, state: 'stopped', expectedState: 'running' });
    expect(stopped.state).toBe('stopped');
    expect(stopped.stoppedAt).toBeTruthy();
    await expect(registry.updateRuntimeState({ runtimeId: runtime.runtimeId, state: 'failed', expectedState: 'running' }))
      .rejects.toMatchObject({ name: 'SandboxRuntimeStateConflictError' });
    expect((await registry.getRuntime(runtime.runtimeId))?.state).toBe('stopped');
  });
});
