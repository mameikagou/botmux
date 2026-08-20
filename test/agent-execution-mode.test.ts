import { describe, expect, it } from 'vitest';
import { ensureSandboxPrincipalForFork } from '../src/core/agent-principal-runtime.js';
import type { DaemonSession } from '../src/core/types.js';
import { handleAgentCredentialsApi } from '../src/dashboard/agent-credentials-api.js';
import { podmanExecutionForSession } from '../src/core/worker-pool.js';

function daemonSession(): DaemonSession {
  return {
    session: {
      sessionId: 'session-execution-mode',
      title: 'execution mode',
      rootMessageId: 'om_root',
      chatId: 'oc_chat',
      chatType: 'p2p',
      status: 'active',
      createdAt: new Date(0).toISOString(),
      ownerOpenId: 'ou_owner',
      larkAppId: 'cli_app',
    } as DaemonSession['session'],
    worker: null,
    workerPort: null,
    workerToken: null,
    larkAppId: 'cli_app',
    chatId: 'oc_chat',
    chatType: 'p2p',
    scope: 'thread',
    spawnedAt: 0,
    cliVersion: 'test',
    lastMessageAt: 0,
    hasHistory: false,
    ownerOpenId: 'ou_owner',
  };
}

describe('principal execution mode boundary', () => {
  it('freezes native mode once and never falls back to the bot Podman profile', async () => {
    const ds = daemonSession();
    // session-manager may pre-seed the candidate profile before the principal
    // boundary resolves the app-scoped execution mode.
    ds.session.execution = { type: 'podman' } as any;
    let modeLookups = 0;
    let credentialLookups = 0;
    const persisted: string[] = [];
    const repository = {
      resolveExecutionModeForNewInstance: async () => {
        modeLookups += 1;
        return {
          principal: {} as never,
          executionMode: 'native' as const,
        };
      },
      resolveForNewInstance: async () => {
        credentialLookups += 1;
        throw new Error('native must not resolve Podman credentials');
      },
    };
    const execution = { type: 'podman' as const } as any;
    await ensureSandboxPrincipalForFork({
      ds,
      execution,
      cliId: 'claude-code',
      repository,
      persist: session => persisted.push(session.executionMode ?? 'missing'),
    });
    expect(ds.session.executionMode).toBe('native');
    expect(ds.session.execution).toBeUndefined();
    expect(podmanExecutionForSession(ds.session, execution)).toBeUndefined();
    expect(modeLookups).toBe(1);
    expect(credentialLookups).toBe(0);

    await ensureSandboxPrincipalForFork({ ds, execution, cliId: 'claude-code', repository });
    expect(modeLookups).toBe(1);
    expect(credentialLookups).toBe(0);
    expect(persisted).toEqual(['native']);
  });

  it('freezes Podman mode before reading the per-principal credential', async () => {
    const ds = daemonSession();
    let modeLookups = 0;
    let credentialLookups = 0;
    const repository = {
      resolveExecutionModeForNewInstance: async () => {
        modeLookups += 1;
        return {
          principal: {} as never,
          executionMode: 'podman' as const,
        };
      },
      resolveForNewInstance: async () => {
        credentialLookups += 1;
        return {
          principal: {} as never,
          credential: {} as never,
          principalBinding: {
            larkAppId: 'cli_app', openId: 'ou_owner', enabled: true as const,
            canOpenMemory: false, cliId: 'claude-code' as const,
            credentialVersion: 1, credentialKind: 'api' as const,
          },
          credentialBinding: {
            kind: 'api' as const,
            credentialVersion: 1,
            baseUrl: 'https://api.example.test',
            model: 'test-model',
          },
          credentialSecret: 'test-secret',
        };
      },
    };
    await ensureSandboxPrincipalForFork({
      ds,
      execution: { type: 'podman' as const } as any,
      cliId: 'claude-code',
      repository,
    });
    expect(ds.session.executionMode).toBe('podman');
    expect(ds.session.execution).toEqual({ type: 'podman' });
    expect(modeLookups).toBe(1);
    expect(credentialLookups).toBe(1);
    expect(ds.credentialSecret).toBe('test-secret');
  });

  it('hydrates the missing native owner capability posture only on a cold fork', async () => {
    const ds = daemonSession();
    ds.session.executionMode = 'native';
    let lookups = 0;
    const repository = {
      resolveExecutionModeForNewInstance: async () => {
        lookups += 1;
        return {
          principal: { canOpenMemory: false },
          executionMode: 'native' as const,
          principalSkills: [],
        } as any;
      },
      resolveForNewInstance: async () => { throw new Error('not used'); },
    };
    await ensureSandboxPrincipalForFork({ ds, cliId: 'codex', repository });
    expect(ds.session.ownerCanOpenMemory).toBe(false);
    expect(lookups).toBe(1);

    await ensureSandboxPrincipalForFork({ ds, cliId: 'codex', repository });
    expect(lookups).toBe(1);
  });

  it('keeps execution-mode mutation owner-only at the pairing API', async () => {
    let mode: 'native' | 'podman' = 'podman';
    const principal = {
      larkAppId: 'cli_app',
      openId: 'ou_guest',
      enabled: true,
      canOpenMemory: false,
      executionMode: mode,
      createdAt: '',
      updatedAt: '',
    } as const;
    const repository = {
      getPrincipal: async () => ({ ...principal, executionMode: mode }),
      getCredential: async () => undefined,
      putCredential: async () => { throw new Error('not used'); },
      deleteCredential: async () => false,
      setExecutionMode: async (_key: unknown, next: 'native' | 'podman') => {
        mode = next;
        return { ...principal, executionMode: mode };
      },
    };
    const guest = await handleAgentCredentialsApi({
      method: 'PATCH',
      path: '/api/agent/principal',
      principal: { larkAppId: 'cli_app', openId: 'ou_guest' },
      body: { executionMode: 'native' },
    }, { repository });
    expect(guest).toEqual({ status: 403, body: { ok: false, error: 'principal_owner_required' } });
    expect(mode).toBe('podman');

    const owner = await handleAgentCredentialsApi({
      method: 'PATCH',
      path: '/api/agent/principal',
      principal: { larkAppId: 'cli_app', openId: 'ou_guest' },
      ownerOpenId: 'ou_guest',
      body: { executionMode: 'native' },
    }, { repository });
    expect(owner.status).toBe(200);
    expect(mode).toBe('native');
  });
});
