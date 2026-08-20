import { describe, expect, it } from 'vitest';
import { AgentPrincipalRepository, type SqlPool } from '../src/services/agent-principal-store.js';

const key = { larkAppId: 'cli_guest', openId: 'ou_guest' } as const;
const user = {
  sandboxUserId: 'guest-a', enabled: true, canOpenMemory: false, executionMode: 'podman' as const,
  podGeneration: 7, createdAt: '2026-08-20T00:00:00.000Z', updatedAt: '2026-08-20T00:00:00.000Z',
};
const identity = { ...key, sandboxUserId: user.sandboxUserId, enabled: true, createdAt: user.createdAt, updatedAt: user.updatedAt };

function dbWithPrincipal(): SqlPool {
  return {
    query: async <Row = Record<string, unknown>>(text: string): Promise<{ rows: Row[] }> => {
      if (text.includes('LEFT JOIN agent_model_credentials')) {
        return { rows: [{
          lark_app_id: key.larkAppId, open_id: key.openId, enabled: true, can_openmemory: false,
          execution_mode: 'podman', created_at: new Date(0), updated_at: new Date(0),
          credential_kind: null, encrypted_secret: undefined, secret_nonce: undefined,
          principal_skills: null,
        }] as Row[] };
      }
      if (text.includes('SELECT lark_app_id, open_id, enabled')) {
        return { rows: [{
          lark_app_id: key.larkAppId, open_id: key.openId, enabled: true, can_openmemory: false,
          execution_mode: 'podman', created_at: new Date(0), updated_at: new Date(0),
        }] as Row[] };
      }
      if (text.includes('SELECT enabled FROM agent_principals')) {
        return { rows: [{ enabled: true }] as Row[] };
      }
      throw new Error(`unexpected query ${text}`);
    },
    connect: async () => { throw new Error('stable path must not open a legacy credential transaction'); },
  };
}

function stableRegistry(options: { missing?: boolean } = {}) {
  const calls: string[] = [];
  const registry = {
    calls,
    resolveUserForIdentity: async () => {
      calls.push('resolve');
      if (options.missing) throw Object.assign(new Error('not found'), { code: 'not_found' });
      return { user, identity };
    },
    readSecret: async (_user: unknown, harness: string) => {
      calls.push(`read:${harness}`);
      return {
        metadata: {
          sandboxUserId: user.sandboxUserId, harness, credentialKind: 'api' as const,
          baseUrl: 'https://api.example.test', model: 'guest-model', credentialVersion: 3,
          updatedAt: user.updatedAt,
        },
        secret: 'stable-secret',
      };
    },
    getCredential: async (_user: unknown, harness: string) => {
      calls.push(`get:${harness}`);
      return {
        sandboxUserId: user.sandboxUserId, harness, credentialKind: 'api' as const,
        baseUrl: 'https://api.example.test', model: `${harness}-model`, credentialVersion: 3,
        updatedAt: user.updatedAt,
      };
    },
    putCredential: async (input: { harness: string }) => {
      calls.push(`put:${input.harness}`);
      return {
        sandboxUserId: user.sandboxUserId, harness: input.harness, credentialKind: 'api' as const,
        baseUrl: 'https://api.example.test', model: 'new-model', credentialVersion: 4,
        updatedAt: user.updatedAt,
      };
    },
    deleteCredential: async () => false,
  };
  return registry;
}

describe('V4 stable user principal boundary', () => {
  it('freezes stable user and pod generation and reads only that harness credential', async () => {
    const registry = stableRegistry();
    const repository = new AgentPrincipalRepository(dbWithPrincipal(), Buffer.alloc(32, 1), registry);
    const resolved = await repository.resolveForNewInstance({ key, cliId: 'claude-code', ownerOpenId: key.openId });
    expect(resolved.credentialSecret).toBe('stable-secret');
    expect(resolved.principalBinding.sandboxUserId).toBe('guest-a');
    expect(resolved.principalBinding.podGeneration).toBe(7);
    expect(resolved.principalBinding.credentialKind).toBe('api');
    expect(registry.calls).toContain('read:claude-code');
  });

  it('uses an explicit dashboard harness instead of whichever stable slot sorts first', async () => {
    const registry = stableRegistry();
    const repository = new AgentPrincipalRepository(dbWithPrincipal(), Buffer.alloc(32, 1), registry);
    const metadata = await repository.getCredential(key, 'claude-code');
    expect(metadata?.model).toBe('claude-code-model');
    expect(registry.calls).toEqual(['resolve', 'get:claude-code']);
  });

  it('does not fall back to an old app/open credential for an unmigrated guest', async () => {
    const registry = stableRegistry({ missing: true });
    const repository = new AgentPrincipalRepository(dbWithPrincipal(), Buffer.alloc(32, 1), registry);
    await expect(repository.resolveForNewInstance({ key, cliId: 'claude-code', ownerOpenId: key.openId }))
      .rejects.toMatchObject({ code: 'not_found' });
  });

  it('makes the stable user+harness row authoritative for credential writes', async () => {
    const registry = stableRegistry();
    const repository = new AgentPrincipalRepository(dbWithPrincipal(), Buffer.alloc(32, 1), registry);
    const metadata = await repository.putCredential({
      key,
      harness: 'claude-code',
      credentialKind: 'api',
      secret: 'stable-write-secret',
      baseUrl: 'https://api.example.test',
      model: 'new-model',
    });
    expect(metadata.credentialVersion).toBe(4);
    expect(registry.calls).toEqual(['resolve', 'put:claude-code']);
  });
});
