import { afterAll, describe, expect, it } from 'vitest';
import {
  AgentPrincipalLookupError,
  AgentPrincipalRepository,
  CodexLoginTaskConflictError,
  applyAgentPrincipalMigration,
  createAgentPrincipalPool,
  rollbackAgentPrincipalMigration,
} from '../src/services/agent-principal-store.js';

/**
 * Opt-in only: this test is deliberately inert unless an operator supplies a
 * disposable PostgreSQL URL and explicitly enables the integration profile.
 * It must never touch the live research database during ordinary CI or local
 * unit runs.
 */
const enabled = process.env.BOTMUX_T6_PG_INTEGRATION === '1'
  && typeof process.env.BOTMUX_AGENT_DATABASE_URL === 'string'
  && process.env.BOTMUX_AGENT_DATABASE_URL.trim().length > 0;

describe.skipIf(!enabled)('T6 temporary PostgreSQL integration', () => {
  const pool = enabled ? createAgentPrincipalPool(process.env.BOTMUX_AGENT_DATABASE_URL) : undefined;
  const masterKey = Buffer.alloc(32, 0x5a);
  const repository = pool ? new AgentPrincipalRepository(pool, masterKey) : undefined;
  const appA = `t6_test_a_${process.pid}`;
  const appB = `t6_test_b_${process.pid}`;
  const owner = { larkAppId: appA, openId: 'ou_t6_owner' };

  afterAll(async () => {
    if (!pool) return;
    await rollbackAgentPrincipalMigration(pool).catch(() => undefined);
    await pool.end?.();
  });

  it('round-trips a composite principal and encrypted credential, then rejects another app', async () => {
    if (!pool || !repository) return;
    await applyAgentPrincipalMigration(pool);
    await repository.seedPrincipals([
      { key: owner, canOpenMemory: true },
      { key: { larkAppId: appB, openId: owner.openId }, canOpenMemory: false },
    ]);
    const stored = await repository.putCredential({
      key: owner,
      credentialKind: 'api',
      secret: 't6-disposable-secret',
      baseUrl: 'https://api.example.test',
      model: 'test-model',
    });
    expect(stored.credentialVersion).toBe(1);
    const resolved = await repository.resolveForNewInstance({ key: owner, cliId: 'claude-code', ownerOpenId: owner.openId });
    expect(resolved.credentialSecret).toBe('t6-disposable-secret');
    expect(resolved.principalBinding.larkAppId).toBe(appA);
    await expect(repository.resolveForNewInstance({ key: { larkAppId: appB, openId: owner.openId }, cliId: 'claude-code', ownerOpenId: owner.openId }))
      .rejects.toBeInstanceOf(AgentPrincipalLookupError);
  });

  it('pins login-task leases to one principal and reaps an expired lease', async () => {
    if (!pool || !repository) return;
    const taskOne = '00000000-0000-4000-8000-000000000061';
    const taskTwo = '00000000-0000-4000-8000-000000000062';
    await repository.beginCodexLoginTask({
      key: owner,
      taskId: taskOne,
      leaseExpiresAt: new Date(Date.now() + 60_000),
    });
    await expect(repository.beginCodexLoginTask({
      key: owner,
      taskId: taskTwo,
      leaseExpiresAt: new Date(Date.now() + 60_000),
    })).rejects.toBeInstanceOf(CodexLoginTaskConflictError);
    await pool.query(
      `UPDATE agent_codex_login_tasks SET lease_expires_at = now() - interval '1 second' WHERE task_id = $1::uuid`,
      [taskOne],
    );
    await repository.beginCodexLoginTask({
      key: owner,
      taskId: taskTwo,
      leaseExpiresAt: new Date(Date.now() + 60_000),
    });
    await repository.updateCodexLoginTask(taskTwo, { status: 'failed', errorCode: 'test_cleanup' });
  });

  it('serializes two first credential writers with expectedVersion zero', async () => {
    if (!pool || !repository) return;
    const raceKey = { larkAppId: appA, openId: 'ou_t6_cas_race' };
    await repository.seedPrincipals([{ key: raceKey }]);
    const outcomes = await Promise.allSettled([
      repository.putCredential({
        key: raceKey,
        credentialKind: 'api',
        secret: 't6-cas-secret-a',
        baseUrl: 'https://api.example.test',
        model: 'race-a',
        expectedVersion: 0,
      }),
      repository.putCredential({
        key: raceKey,
        credentialKind: 'api',
        secret: 't6-cas-secret-b',
        baseUrl: 'https://api.example.test',
        model: 'race-b',
        expectedVersion: 0,
      }),
    ]);
    expect(outcomes.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    const rejected = outcomes.filter((result): result is PromiseRejectedResult => result.status === 'rejected');
    expect(rejected).toHaveLength(1);
    expect(rejected[0]?.reason).toMatchObject({ name: 'CredentialVersionConflictError' });
    const final = await repository.readSecret(raceKey);
    expect(final.metadata.credentialVersion).toBe(1);
    expect(['race-a', 'race-b']).toContain(final.metadata.model);
    expect(['t6-cas-secret-a', 't6-cas-secret-b']).toContain(final.secret);
  });
});
