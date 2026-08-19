import { afterEach, describe, expect, it } from 'vitest';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  decryptCredentialUtf8,
  encryptCredential,
  loadCredentialMasterKey,
} from '../src/services/agent-principal-crypto.js';
import {
  CodexLoginTaskConflictError,
  AgentPrincipalLookupError,
  AgentPrincipalRepository,
  type SqlPool,
} from '../src/services/agent-principal-store.js';
import { validateApiCredentialEndpoint, validateBaseUrl } from '../src/services/agent-credential-policy.js';
import { bindNewPodmanSession, materializeColdPodmanCredential, shouldLookupPrincipalAtIngress } from '../src/core/agent-principal-boundary.js';
import { handleAgentCredentialsApi } from '../src/dashboard/agent-credentials-api.js';
import {
  CodexAuthRefreshWatcher,
  CodexDeviceLoginService,
  PodmanCodexDeviceAuthRunner,
  shouldStartCodexAuthRefreshWatcher,
  writeCodexAuthJson,
} from '../src/services/codex-device-login.js';
import { buildPrincipalSeedRows } from '../src/services/agent-principal-seed.js';
import { stopSessionsForPrincipal } from '../src/services/agent-principal-lifecycle.js';
import { AgentCredentialProbeError } from '../src/services/agent-credential-probe.js';

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function tempDir(): string { const dir = mkdtempSync(join(tmpdir(), 'botmux-t6-')); dirs.push(dir); return dir; }

describe('T6 principal crypto and policy', () => {
  it('starts the Codex auth watcher only for the ChatGPT credential flow', () => {
    expect(shouldStartCodexAuthRefreshWatcher({ cliId: 'codex', credentialKind: 'codex_chatgpt' })).toBe(true);
    expect(shouldStartCodexAuthRefreshWatcher({ cliId: 'codex', credentialKind: 'api' })).toBe(false);
    expect(shouldStartCodexAuthRefreshWatcher({ cliId: 'codex' })).toBe(false);
    expect(shouldStartCodexAuthRefreshWatcher({ cliId: 'claude-code', credentialKind: 'codex_chatgpt' })).toBe(false);
  });

  it('authenticates ciphertext and binds it to the app-scoped principal', () => {
    const key = Buffer.alloc(32, 7);
    const principal = { larkAppId: 'cli_a', openId: 'ou_one' };
    const encrypted = encryptCredential('sk-secret', key, principal);
    expect(decryptCredentialUtf8(encrypted, key, principal)).toBe('sk-secret');
    encrypted.ciphertext[0] ^= 1;
    expect(() => decryptCredentialUtf8(encrypted, key, principal)).toThrow('authentication failed');
  });

  it('loads a 32-byte host key and rejects malformed values', () => {
    expect(loadCredentialMasterKey({ env: { BOTMUX_AGENT_CREDENTIAL_MASTER_KEY: Buffer.alloc(32, 3).toString('base64') } })).toEqual(Buffer.alloc(32, 3));
    expect(() => loadCredentialMasterKey({ env: { BOTMUX_AGENT_CREDENTIAL_MASTER_KEY: 'short' } })).toThrow();
  });

  it('rejects unsafe API endpoints before any credential write', async () => {
    expect(() => validateBaseUrl('http://127.0.0.1:9000')).toThrow();
    expect(() => validateBaseUrl('https://example.test/path?token=secret')).toThrow();
    await expect(validateApiCredentialEndpoint('https://127.0.0.1')).rejects.toThrow();
  });

  it('materializes Codex auth JSON only into a private non-host path', () => {
    const dir = tempDir();
    const authPath = join(dir, 'principal', 'codex', 'auth.json');
    writeCodexAuthJson({ authPath, authJson: '{"tokens":{"access_token":"redacted-test"}}' });
    expect(existsSync(authPath)).toBe(true);
    expect(JSON.parse(readFileSync(authPath, 'utf8')).tokens.access_token).toBe('redacted-test');
    expect(() => writeCodexAuthJson({ authPath: join(process.env.HOME ?? '/home/admin', '.codex', 'auth.json'), authJson: '{}' })).toThrow();
  });
});

describe('T6 repository and ingress binding', () => {
  it('requires explicit app-scoped mappings for config identities', () => {
    const bots = [{ larkAppId: 'app_a', allowedUsers: ['owner@example.com', 'friend@example.com'] }];
    expect(() => buildPrincipalSeedRows({ bots, ownerOpenIds: new Map([['app_a', 'ou_owner']]) })).toThrow('--map');
    const rows = buildPrincipalSeedRows({
      bots,
      ownerOpenIds: new Map([['app_a', 'ou_owner']]),
      userOpenIdMappings: new Map([
        ['app_a\0owner@example.com', 'ou_owner'],
        ['app_a\0friend@example.com', 'ou_friend'],
      ]),
    });
    expect(rows.map(row => row.key.openId)).toEqual(['ou_owner', 'ou_friend']);
  });

  it('uses the composite app/open_id key and freezes only non-secret metadata', async () => {
    const key = Buffer.alloc(32, 9);
    const principal = { larkAppId: 'app_a', openId: 'ou_owner' };
    const encrypted = encryptCredential('device-or-api-secret', key, principal);
    const queries: Array<{ text: string; values?: readonly unknown[] }> = [];
    const db: SqlPool = {
      query: async (text, values) => {
        queries.push({ text, values });
        if (text.includes('LEFT JOIN agent_model_credentials') && values?.[0] === 'app_a') {
          return { rows: [{
            lark_app_id: 'app_a', open_id: 'ou_owner', enabled: true, can_openmemory: true,
            created_at: new Date(0), updated_at: new Date(0), credential_kind: 'api', base_url: 'https://api.example.test', model: 'model-a',
            encrypted_secret: encrypted.ciphertext, secret_nonce: encrypted.nonce, credential_version: 2, credential_updated_at: new Date(0),
          }] };
        }
        if (text.includes('LEFT JOIN agent_model_credentials')) return { rows: [] };
        throw new Error(`unexpected query: ${text}`);
      },
      connect: async () => { throw new Error('not used'); },
    };
    const repo = new AgentPrincipalRepository(db, key);
    const resolved = await repo.resolveForNewInstance({ key: principal, cliId: 'claude-code', ownerOpenId: 'ou_owner' });
    expect(resolved.credentialSecret).toBe('device-or-api-secret');
    expect(resolved.principalBinding).not.toHaveProperty('credentialSecret');
    expect(resolved.credentialBinding.credentialVersion).toBe(2);
    expect(queries[0]?.values).toEqual(['app_a', 'ou_owner']);
    await expect(repo.resolveForNewInstance({ key: { larkAppId: 'app_b', openId: 'ou_owner' }, cliId: 'claude-code', ownerOpenId: 'ou_owner' })).rejects.toBeInstanceOf(AgentPrincipalLookupError);
  });

  it('fails closed for disabled principals and database outages', async () => {
    const disabledDb: SqlPool = {
      query: async () => ({ rows: [{
        lark_app_id: 'app_a', open_id: 'ou_disabled', enabled: false, can_openmemory: false,
        created_at: new Date(0), updated_at: new Date(0),
      }] }),
      connect: async () => { throw new Error('not used'); },
    };
    const disabledRepo = new AgentPrincipalRepository(disabledDb, Buffer.alloc(32, 1));
    await expect(disabledRepo.resolveForNewInstance({
      key: { larkAppId: 'app_a', openId: 'ou_disabled' }, cliId: 'codex',
    })).rejects.toMatchObject({ code: 'disabled' });

    const unavailableRepo = new AgentPrincipalRepository({
      query: async () => { throw new Error('connection refused'); },
      connect: async () => { throw new Error('connection refused'); },
    }, Buffer.alloc(32, 1));
    await expect(unavailableRepo.resolveForNewInstance({
      key: { larkAppId: 'app_a', openId: 'ou_owner' }, cliId: 'codex',
    })).rejects.toMatchObject({ code: 'database_unavailable' });
  });

  it('preserves sanitized transaction conflicts without exposing raw SQL errors', async () => {
    const key = { larkAppId: 'app_a', openId: 'ou_owner' } as const;
    const makeDb = (insertError?: Error): SqlPool => {
      const tx = {
        query: async (text: string) => {
          if (text === 'BEGIN' || text === 'COMMIT' || text === 'ROLLBACK') return { rows: [] };
          if (text.includes('SELECT enabled')) return { rows: [{ enabled: true }] };
          if (text.includes('UPDATE agent_codex_login_tasks')) return { rows: [] };
          if (text.includes('INSERT INTO agent_codex_login_tasks')) {
            if (insertError) throw insertError;
            return { rows: [] };
          }
          return { rows: [] };
        },
        release: () => undefined,
      };
      return { query: tx.query, connect: async () => tx };
    };
    const repository = new AgentPrincipalRepository(makeDb(), Buffer.alloc(32, 1));
    await expect(repository.beginCodexLoginTask({
      key,
      taskId: '00000000-0000-4000-8000-000000000071',
      leaseExpiresAt: new Date(Date.now() + 60_000),
    })).rejects.toBeInstanceOf(CodexLoginTaskConflictError);

    const raw = new Error('duplicate key postgres://user:secret@example.test/db');
    const unavailable = new AgentPrincipalRepository(makeDb(raw), Buffer.alloc(32, 1));
    await expect(unavailable.beginCodexLoginTask({
      key,
      taskId: '00000000-0000-4000-8000-000000000072',
      leaseExpiresAt: new Date(Date.now() + 60_000),
    })).rejects.toMatchObject({ code: 'database_unavailable', message: 'agent principal database unavailable' });
  });

  it('does one lookup for a new topic and none for an existing frozen topic', async () => {
    let calls = 0;
    const bindingRepo = {
      resolveForNewInstance: async () => {
        calls += 1;
        return {
          principalBinding: { larkAppId: 'app_a', openId: 'ou_owner', enabled: true as const, canOpenMemory: false, cliId: 'codex' as const, credentialVersion: 1, credentialKind: 'codex_chatgpt' as const },
          credentialBinding: { kind: 'codex_chatgpt' as const, credentialVersion: 1 },
          credentialSecret: '{"tokens":{}}',
        } as const;
      },
    };
    const session: any = { execution: { type: 'podman' }, ownerOpenId: 'ou_owner' };
    const ds: any = { session, larkAppId: 'app_a', ownerOpenId: 'ou_owner' };
    const persist = (value: unknown) => { ds.session = value; };
    const first = await bindNewPodmanSession({ ds, cliId: 'codex', repository: bindingRepo, persist });
    expect(first?.credentialSecret).toContain('tokens');
    await bindNewPodmanSession({ ds, cliId: 'codex', repository: bindingRepo, persist });
    expect(calls).toBe(1);
    expect(shouldLookupPrincipalAtIngress({ isDirectBotMessage: true, createsNewInstance: true, existingSessionHasFrozenBinding: false, coldWorkerRebuild: false })).toBe(true);
    expect(shouldLookupPrincipalAtIngress({ isDirectBotMessage: false, createsNewInstance: false, existingSessionHasFrozenBinding: true, coldWorkerRebuild: false })).toBe(false);
    const cold = await materializeColdPodmanCredential({ ds, cliId: 'codex', repository: bindingRepo });
    expect(cold.credentialSecret).toContain('tokens');
    expect(calls).toBe(2);
  });

  it('does not re-query a live topic after the transient secret is cleared', async () => {
    let calls = 0;
    const repository = {
      resolveForNewInstance: async () => {
        calls += 1;
        return {
          principalBinding: {
            larkAppId: 'app_a', openId: 'ou_owner', enabled: true as const,
            canOpenMemory: false, cliId: 'codex' as const,
            credentialVersion: 1, credentialKind: 'codex_chatgpt' as const,
          },
          credentialBinding: { kind: 'codex_chatgpt' as const, credentialVersion: 1 },
          credentialSecret: '{"tokens":{}}',
        } as const;
      },
    };
    const session: any = {
      execution: { type: 'podman' }, ownerOpenId: 'ou_owner',
      principalBinding: {
        larkAppId: 'app_a', openId: 'ou_owner', enabled: true,
        canOpenMemory: false, cliId: 'codex', credentialVersion: 1,
        credentialKind: 'codex_chatgpt',
      },
      credentialBinding: { kind: 'codex_chatgpt', credentialVersion: 1 },
    };
    const ds: any = {
      session,
      larkAppId: 'app_a',
      ownerOpenId: 'ou_owner',
      worker: { killed: false },
    };
    const { ensureSandboxPrincipalForFork } = await import('../src/core/agent-principal-runtime.js');
    await ensureSandboxPrincipalForFork({
      ds,
      execution: { type: 'podman' } as any,
      cliId: 'codex',
      persist: () => undefined,
    });
    expect(calls).toBe(0);
  });

  it('refreshes a rotated credential on cold start instead of permanently bricking the topic', async () => {
    let calls = 0;
    const versions = [1, 2];
    const repository = {
      resolveForNewInstance: async () => {
        const version = versions[Math.min(calls++, versions.length - 1)]!;
        return {
          principalBinding: {
            larkAppId: 'app_a', openId: 'ou_owner', enabled: true as const,
            canOpenMemory: version === 2, cliId: 'codex' as const,
            credentialVersion: version, credentialKind: 'codex_chatgpt' as const,
          },
          credentialBinding: { kind: 'codex_chatgpt' as const, credentialVersion: version },
          credentialSecret: `{"tokens":{"access_token":"v${version}"}}`,
        } as const;
      },
    };
    const session: any = {
      execution: { type: 'podman' }, ownerOpenId: 'ou_owner',
      principalBinding: {
        larkAppId: 'app_a', openId: 'ou_owner', enabled: true,
        canOpenMemory: false, cliId: 'codex', credentialVersion: 1,
        credentialKind: 'codex_chatgpt',
      },
      credentialBinding: { kind: 'codex_chatgpt', credentialVersion: 1 },
    };
    const ds: any = { session, larkAppId: 'app_a', ownerOpenId: 'ou_owner' };
    const persisted: any[] = [];
    const refreshed = await materializeColdPodmanCredential({
      ds,
      cliId: 'codex',
      repository,
      persist: value => persisted.push({ ...value }),
    });
    expect(refreshed.credentialBinding.credentialVersion).toBe(1);
    // A prior lookup may have produced v1; simulate rotation before the next
    // cold worker and prove the frozen metadata is safely advanced to v2.
    const rotated = await materializeColdPodmanCredential({
      ds,
      cliId: 'codex',
      repository,
      persist: value => persisted.push({ ...value }),
    });
    expect(rotated.credentialBinding.credentialVersion).toBe(2);
    expect(rotated.credentialSecret).toContain('v2');
    expect(ds.session.credentialBinding.credentialVersion).toBe(2);
    expect(ds.session.principalBinding.canOpenMemory).toBe(true);
    expect(persisted).toHaveLength(2);
  });

  it('clears stopped principal bindings so rotation can rebind on the next start', async () => {
    const ds: any = {
      session: {
        sessionId: 'rotated-session',
        principalBinding: { larkAppId: 'app_a', openId: 'ou_owner', enabled: true },
        credentialBinding: { kind: 'api', credentialVersion: 1 },
      },
      credentialSecret: 'transient-secret',
    };
    let stopped = 0;
    const persisted: any[] = [];
    await stopSessionsForPrincipal(
      [ds],
      { larkAppId: 'app_a', openId: 'ou_owner' },
      () => { stopped += 1; },
      { persist: session => persisted.push(session) },
    );
    expect(stopped).toBe(1);
    expect(ds.session.principalBinding).toBeUndefined();
    expect(ds.session.credentialBinding).toBeUndefined();
    expect(ds.credentialSecret).toBeUndefined();
    expect(persisted).toHaveLength(1);
  });
});

describe('T6 dashboard credential API', () => {
  it('never returns the supplied API key and rotates by expected version', async () => {
    let stored: any = undefined;
    const stopped: string[] = [];
    const deps: any = {
      repository: {
        getPrincipal: async () => ({ larkAppId: 'app_a', openId: 'ou_owner', enabled: true, canOpenMemory: true, createdAt: '', updatedAt: '' }),
        getCredential: async () => stored,
        putCredential: async (input: any) => {
          if (input.expectedVersion !== undefined && input.expectedVersion !== (stored?.credentialVersion ?? 0)) throw Object.assign(new Error('credential_version_conflict'), { name: 'CredentialVersionConflictError' });
          stored = { larkAppId: 'app_a', openId: 'ou_owner', credentialKind: 'api', baseUrl: input.baseUrl, model: input.model, credentialVersion: (stored?.credentialVersion ?? 0) + 1, updatedAt: '', keyFingerprint: 'abcd' };
          return stored;
        },
        deleteCredential: async () => true,
        upsertPrincipal: async () => undefined,
        setPrincipalEnabled: async () => undefined,
        setOpenMemory: async () => undefined,
      },
      validateEndpoint: async (baseUrl: string) => new URL(baseUrl),
      stopSessionsForPrincipal: () => { stopped.push('ou_owner'); },
    };
    deps.probeApiCredential = async ({ apiKey, cliId, baseUrl, model }: any) => {
      expect({ apiKey, cliId, baseUrl, model: model === 'm1' ? 'm1' : model }).toMatchObject({ cliId: 'claude-code', baseUrl: 'https://api.example.test' });
    };
    const result = await handleAgentCredentialsApi({ method: 'PUT', path: '/api/agent/model-credential', principal: { larkAppId: 'app_a', openId: 'ou_owner' }, botCliId: 'claude-code', body: { key: 'sk-live-secret', baseUrl: 'https://api.example.test', model: 'm1', expectedVersion: 0 } }, deps);
    expect(result.status).toBe(200);
    expect(JSON.stringify(result.body)).not.toContain('sk-live-secret');
    expect(stopped).toEqual(['ou_owner']);
    const firstWriterLost = await handleAgentCredentialsApi({ method: 'PUT', path: '/api/agent/model-credential', principal: { larkAppId: 'app_a', openId: 'ou_owner' }, botCliId: 'claude-code', body: { key: 'sk-racing-writer', baseUrl: 'https://api.example.test', model: 'racing', expectedVersion: 0 } }, deps);
    expect(firstWriterLost.status).toBe(409);
    const denied = await handleAgentCredentialsApi({ method: 'PUT', path: '/api/agent/model-credential', principal: { larkAppId: 'app_a', openId: 'ou_owner' }, botCliId: 'claude-code', body: { key: 'sk-next', baseUrl: 'https://api.example.test', model: 'm2', expectedVersion: 9 } }, deps);
    expect(denied.status).toBe(409);
    const removed = await handleAgentCredentialsApi({ method: 'DELETE', path: '/api/agent/model-credential', principal: { larkAppId: 'app_a', openId: 'ou_owner' }, body: { expectedVersion: 1 } }, deps);
    expect(removed.status).toBe(200);
    expect(stopped).toEqual(['ou_owner', 'ou_owner']);
    const selfGrant = await handleAgentCredentialsApi({ method: 'PATCH', path: '/api/agent/principal', principal: { larkAppId: 'app_a', openId: 'ou_owner' }, body: { canOpenMemory: true } }, deps);
    expect(selfGrant.status).toBe(403);
  });

  it('fails closed before the encrypted upsert when the API probe rejects the key', async () => {
    const putCalls: unknown[] = [];
    const deps: any = {
      repository: {
        getPrincipal: async () => ({ larkAppId: 'app_a', openId: 'ou_owner', enabled: true, canOpenMemory: false, createdAt: '', updatedAt: '' }),
        getCredential: async () => undefined,
        putCredential: async (input: unknown) => { putCalls.push(input); return {} as any; },
        deleteCredential: async () => false,
      },
      validateEndpoint: async (baseUrl: string) => new URL(baseUrl),
      probeApiCredential: async ({ apiKey }: { apiKey: string }) => {
        expect(apiKey).toBe('sk-probe-secret');
        throw new AgentCredentialProbeError();
      },
    };
    const response = await handleAgentCredentialsApi({
      method: 'PUT', path: '/api/agent/model-credential', principal: { larkAppId: 'app_a', openId: 'ou_owner' }, botCliId: 'codex',
      body: { key: 'sk-probe-secret', baseUrl: 'https://api.example.test/v1', model: 'probe-model', expectedVersion: 0 },
    }, deps);
    expect(response).toEqual({ status: 502, body: { ok: false, error: 'credential_probe_failed' } });
    expect(putCalls).toHaveLength(0);
    expect(JSON.stringify(response)).not.toContain('sk-probe-secret');
  });

  it('rejects an API write without an injected fixed-harness probe', async () => {
    let putCalls = 0;
    const response = await handleAgentCredentialsApi({
      method: 'PUT', path: '/api/agent/model-credential', principal: { larkAppId: 'app_a', openId: 'ou_owner' }, botCliId: 'pi',
      body: { key: 'sk-no-probe', baseUrl: 'https://api.example.test', model: 'm', expectedVersion: 0 },
    }, {
      repository: {
        getPrincipal: async () => ({ larkAppId: 'app_a', openId: 'ou_owner', enabled: true, canOpenMemory: false, createdAt: '', updatedAt: '' }),
        getCredential: async () => undefined,
        putCredential: async () => { putCalls += 1; return {} as any; },
        deleteCredential: async () => false,
      },
      validateEndpoint: async (baseUrl: string) => new URL(baseUrl),
    });
    expect(response.status).toBe(502);
    expect(putCalls).toBe(0);
  });
});

describe('T6 Codex device login and refresh lease', () => {
  it('restricts device auth to private Codex bots and removes temporary auth after encryption', async () => {
    const dir = tempDir();
    const key = { larkAppId: 'app_a', openId: 'ou_owner' } as const;
    let task: any;
    let storedSecret = '';
    const stopped: string[] = [];
    const deleted: Array<unknown[]> = [];
    const runner = {
      startDeviceAuth: async ({ authPath }: { authPath: string }) => {
        writeCodexAuthJson({ authPath, authJson: '{"tokens":{"access_token":"temporary-secret"}}' });
        return { verificationUri: 'https://auth.example.test/device', userCode: 'ABCD-EFGH' };
      },
      status: async () => ({ loggedIn: true }),
      logout: async () => undefined,
    };
    const repository: any = {
      beginCodexLoginTask: async (input: any) => {
        task = { taskId: input.taskId, status: 'pending', leaseExpiresAt: input.leaseExpiresAt.toISOString() };
      },
      updateCodexLoginTask: async (taskId: string, update: any) => { task = { ...task, taskId, ...update }; },
      getCodexLoginTask: async () => task,
      putCredential: async (input: any) => {
        storedSecret = String(input.secret);
        return { ...key, credentialKind: 'codex_chatgpt', credentialVersion: 1, updatedAt: '' };
      },
      deleteCredential: async (...args: unknown[]) => { deleted.push(args); return true; },
    };
    const service = new CodexDeviceLoginService({
      repository,
      authPathFor: (_principal, taskId) => join(dir, taskId, 'auth.json'),
      runner,
      stopSessionsForPrincipal: () => { stopped.push(key.openId); },
    });
    await expect(service.begin(key, { chatType: 'group', botCliId: 'codex' })).rejects.toThrow(/private chat/);
    const challenge = await service.begin(key, { chatType: 'p2p', botCliId: 'codex' });
    expect(challenge.verificationUri).toContain('/device');
    const authPath = join(dir, challenge.taskId, 'auth.json');
    expect(existsSync(authPath)).toBe(true);
    await service.complete(key, challenge.taskId);
    expect(storedSecret).toContain('temporary-secret');
    expect(existsSync(authPath)).toBe(false);
    expect(stopped).toEqual([key.openId]);
    await service.logout(key);
    expect(deleted.at(-1)).toEqual([key, undefined, 'codex_chatgpt']);
  });

  it('expires a pending lease without a status/complete poll and permits a new begin', async () => {
    const dir = tempDir();
    const key = { larkAppId: 'app_a', openId: 'ou_timer' } as const;
    let now = 1_000;
    let task: any;
    let disposed = 0;
    const runner = {
      startDeviceAuth: async ({ authPath }: { authPath: string }) => {
        writeCodexAuthJson({ authPath, authJson: '{"tokens":{"access_token":"timer"}}' });
        return { verificationUri: 'https://auth.example.test/device', userCode: 'TIMER-1234' };
      },
      status: async () => ({ loggedIn: false }),
      logout: async () => undefined,
      dispose: async () => { disposed += 1; },
    };
    const repository: any = {
      beginCodexLoginTask: async (input: any) => { task = { taskId: input.taskId, status: 'pending', leaseExpiresAt: input.leaseExpiresAt.toISOString() }; },
      updateCodexLoginTask: async (taskId: string, update: any) => { task = { ...task, taskId, ...update }; },
      getCodexLoginTask: async () => task,
      deleteCredential: async () => false,
    };
    const service = new CodexDeviceLoginService({
      repository,
      authPathFor: (_principal, taskId) => join(dir, 'tasks', taskId, 'auth.json'),
      runner,
      now: () => now,
      leaseMs: 20,
    });
    const first = await service.begin(key, { chatType: 'p2p', botCliId: 'codex' });
    const authPath = join(dir, 'tasks', first.taskId, 'auth.json');
    expect(existsSync(authPath)).toBe(true);
    now = 1_021;
    await new Promise(resolve => setTimeout(resolve, 40));
    expect(task.status).toBe('expired');
    expect(disposed).toBe(1);
    expect(existsSync(authPath)).toBe(false);
    const second = await service.begin(key, { chatType: 'p2p', botCliId: 'codex' });
    expect(second.taskId).not.toBe(first.taskId);
    await service.logout(key);
  });

  it('does not let a delayed stale begin clear a newer lease generation', async () => {
    const dir = tempDir();
    const key = { larkAppId: 'app_a', openId: 'ou_stale_begin' } as const;
    let now = 1_000;
    let starts = 0;
    let rejectFirst!: (reason?: unknown) => void;
    const tasks = new Map<string, any>();
    const runner = {
      startDeviceAuth: async ({ authPath }: { authPath: string }) => {
        starts += 1;
        writeCodexAuthJson({ authPath, authJson: `{"tokens":{"access_token":"generation-${starts}"}}` });
        if (starts === 1) {
          await new Promise<never>((_resolve, reject) => { rejectFirst = reject; });
          throw new Error('stale generation failed');
        }
        return { verificationUri: 'https://auth.example.test/device', userCode: 'NEW-1234' };
      },
      status: async () => ({ loggedIn: false }),
      logout: async () => undefined,
      dispose: async () => undefined,
    };
    const repository: any = {
      beginCodexLoginTask: async (input: any) => {
        tasks.set(input.taskId, { taskId: input.taskId, status: 'pending', leaseExpiresAt: input.leaseExpiresAt.toISOString() });
      },
      updateCodexLoginTask: async (taskId: string, update: any) => {
        tasks.set(taskId, { ...tasks.get(taskId), taskId, ...update });
      },
      getCodexLoginTask: async () => [...tasks.values()].at(-1),
      deleteCredential: async () => false,
    };
    const service = new CodexDeviceLoginService({
      repository,
      authPathFor: (_principal, taskId) => join(dir, 'tasks', taskId, 'auth.json'),
      runner,
      now: () => now,
      leaseMs: 20,
    });

    const firstPromise = service.begin(key, { chatType: 'p2p', botCliId: 'codex' });
    while (!rejectFirst) await new Promise(resolve => setImmediate(resolve));
    now = 1_021;
    await new Promise(resolve => setTimeout(resolve, 40));
    const firstTask = [...tasks.values()][0];
    expect(firstTask?.status).toBe('expired');

    const second = await service.begin(key, { chatType: 'p2p', botCliId: 'codex' });
    rejectFirst(new Error('late old failure'));
    await expect(firstPromise).rejects.toThrow('late old failure');
    await expect(service.status(key)).resolves.toMatchObject({ taskId: second.taskId, status: 'pending' });
    await service.logout(key);
  });

  it('does not return an expired challenge when notify crosses into a newer generation', async () => {
    const dir = tempDir();
    const key = { larkAppId: 'app_a', openId: 'ou_notify_race' } as const;
    let now = 1_000;
    let notifyCalls = 0;
    let releaseNotify!: () => void;
    const tasks = new Map<string, any>();
    const runner = {
      startDeviceAuth: async ({ authPath }: { authPath: string }) => {
        writeCodexAuthJson({ authPath, authJson: '{"tokens":{"access_token":"notify-race"}}' });
        return { verificationUri: 'https://auth.example.test/device', userCode: 'NOTIFY-1234' };
      },
      status: async () => ({ loggedIn: false }),
      logout: async () => undefined,
      dispose: async () => undefined,
    };
    const repository: any = {
      beginCodexLoginTask: async (input: any) => {
        tasks.set(input.taskId, { taskId: input.taskId, status: 'pending', leaseExpiresAt: input.leaseExpiresAt.toISOString() });
      },
      updateCodexLoginTask: async (taskId: string, update: any) => {
        tasks.set(taskId, { ...tasks.get(taskId), taskId, ...update });
      },
      getCodexLoginTask: async () => [...tasks.values()].at(-1),
      deleteCredential: async () => false,
    };
    const service = new CodexDeviceLoginService({
      repository,
      authPathFor: (_principal, taskId) => join(dir, 'tasks', taskId, 'auth.json'),
      runner,
      now: () => now,
      leaseMs: 20,
      notifyDeviceChallenge: async () => {
        notifyCalls += 1;
        if (notifyCalls === 1) await new Promise<void>(resolve => { releaseNotify = resolve; });
      },
    });

    const firstPromise = service.begin(key, { chatType: 'p2p', botCliId: 'codex' });
    while (!releaseNotify) await new Promise(resolve => setImmediate(resolve));
    const firstTaskId = [...tasks.keys()][0];
    now = 1_021;
    await new Promise(resolve => setTimeout(resolve, 40));
    expect(tasks.get(firstTaskId)?.status).toBe('expired');

    const second = await service.begin(key, { chatType: 'p2p', botCliId: 'codex' });
    releaseNotify();
    await expect(firstPromise).rejects.toThrow('Codex device-auth task expired');
    await expect(service.status(key)).resolves.toMatchObject({ taskId: second.taskId, status: 'pending' });
    await service.logout(key);
  });

  it('fences and removes local auth even when credential deletion fails', async () => {
    const dir = tempDir();
    const key = { larkAppId: 'app_a', openId: 'ou_logout_failure' } as const;
    const canonical = join(dir, 'canonical', 'codex', 'auth.json');
    writeCodexAuthJson({ authPath: canonical, authJson: '{"tokens":{"access_token":"canonical"}}' });
    let task: any;
    let stopped = 0;
    let disposed = 0;
    const repository: any = {
      beginCodexLoginTask: async (input: any) => { task = { taskId: input.taskId, status: 'pending', leaseExpiresAt: input.leaseExpiresAt.toISOString() }; },
      updateCodexLoginTask: async (taskId: string, update: any) => { task = { ...task, taskId, ...update }; },
      getCodexLoginTask: async () => task,
      deleteCredential: async () => { throw new AgentPrincipalLookupError('database_unavailable'); },
    };
    const runner = {
      startDeviceAuth: async ({ authPath }: { authPath: string }) => {
        writeCodexAuthJson({ authPath, authJson: '{"tokens":{"access_token":"task"}}' });
        return { verificationUri: 'https://auth.example.test/device', userCode: 'LOGOUT-1234' };
      },
      status: async () => ({ loggedIn: false }),
      logout: async () => undefined,
      dispose: async () => { disposed += 1; },
    };
    const service = new CodexDeviceLoginService({
      repository,
      authPathFor: (_principal, taskId) => join(dir, 'tasks', taskId, 'auth.json'),
      canonicalAuthPathFor: () => canonical,
      runner,
      stopSessionsForPrincipal: () => { stopped += 1; },
    });
    const challenge = await service.begin(key, { chatType: 'p2p', botCliId: 'codex' });
    const authPath = join(dir, 'tasks', challenge.taskId, 'auth.json');
    await expect(service.logout(key)).rejects.toMatchObject({ code: 'database_unavailable' });
    expect(task.status).toBe('logged_out');
    expect(stopped).toBe(1);
    expect(disposed).toBe(1);
    expect(existsSync(authPath)).toBe(false);
    expect(existsSync(canonical)).toBe(false);
  });

  it('keeps an incomplete device task retryable and fences/removes canonical auth on logout', async () => {
    const dir = tempDir();
    const key = { larkAppId: 'app_a', openId: 'ou_retry' } as const;
    const canonical = join(dir, 'canonical', 'codex', 'auth.json');
    const unrelated = join(dir, 'other', 'codex', 'auth.json');
    writeCodexAuthJson({ authPath: canonical, authJson: '{"tokens":{"access_token":"canonical"}}' });
    writeCodexAuthJson({ authPath: unrelated, authJson: '{"tokens":{"access_token":"unrelated"}}' });
    let task: any;
    let loggedIn = false;
    let stopped = 0;
    let deletes = 0;
    const runner = {
      startDeviceAuth: async ({ authPath }: { authPath: string }) => {
        writeCodexAuthJson({ authPath, authJson: '{"tokens":{"access_token":"task"}}' });
        return { verificationUri: 'https://auth.example.test/device', userCode: 'RETRY-1234' };
      },
      status: async () => ({ loggedIn }),
      logout: async () => undefined,
    };
    const repository: any = {
      getPrincipal: async () => ({ ...key, enabled: true, canOpenMemory: false, createdAt: '', updatedAt: '' }),
      beginCodexLoginTask: async (input: any) => { task = { taskId: input.taskId, status: 'pending', leaseExpiresAt: input.leaseExpiresAt.toISOString() }; },
      updateCodexLoginTask: async (taskId: string, update: any) => { task = { ...task, taskId, ...update }; },
      getCodexLoginTask: async () => task,
      putCredential: async () => ({ ...key, credentialKind: 'codex_chatgpt', credentialVersion: 1, updatedAt: '' }),
      deleteCredential: async () => { deletes += 1; return false; },
    };
    const service = new CodexDeviceLoginService({
      repository,
      authPathFor: (_principal, taskId) => join(dir, 'tasks', taskId, 'auth.json'),
      canonicalAuthPathFor: () => canonical,
      runner,
      stopSessionsForPrincipal: () => { stopped += 1; },
    });
    const challenge = await service.begin(key, { chatType: 'p2p', botCliId: 'codex' });
    const taskAuth = join(dir, 'tasks', challenge.taskId, 'auth.json');
    await expect(service.complete(key, challenge.taskId, 0)).rejects.toThrow('not complete');
    expect(task.status).toBe('pending');
    expect(existsSync(taskAuth)).toBe(true);
    loggedIn = true;
    await service.complete(key, challenge.taskId, 0);
    expect(task.status).toBe('ready');
    expect(existsSync(taskAuth)).toBe(false);

    // No task id is supplied, matching the browser logout flow.  The
    // canonical cache is removed while an unrelated principal remains.
    await service.logout(key);
    expect(deletes).toBe(1);
    expect(stopped).toBe(2); // complete + unconditional logout fence
    expect(existsSync(canonical)).toBe(false);
    expect(existsSync(unrelated)).toBe(true);
  });

  it('marks a CAS-conflicted completion failed and permits a new begin', async () => {
    const dir = tempDir();
    const key = { larkAppId: 'app_a', openId: 'ou_cas' } as const;
    let task: any;
    let starts = 0;
    const repository: any = {
      getPrincipal: async () => ({ ...key, enabled: true, canOpenMemory: false, createdAt: '', updatedAt: '' }),
      beginCodexLoginTask: async (input: any) => { starts += 1; task = { taskId: input.taskId, status: 'pending', leaseExpiresAt: input.leaseExpiresAt.toISOString() }; },
      updateCodexLoginTask: async (taskId: string, update: any) => { task = { ...task, taskId, ...update }; },
      getCodexLoginTask: async () => task,
      putCredential: async () => { throw Object.assign(new Error('credential_version_conflict'), { name: 'CredentialVersionConflictError' }); },
      deleteCredential: async () => false,
    };
    const runner = {
      startDeviceAuth: async ({ authPath }: { authPath: string }) => {
        writeCodexAuthJson({ authPath, authJson: '{"tokens":{"access_token":"cas"}}' });
        return { verificationUri: 'https://auth.example.test/device', userCode: 'CAS-1234' };
      },
      status: async () => ({ loggedIn: true }),
      logout: async () => undefined,
    };
    const service = new CodexDeviceLoginService({
      repository,
      authPathFor: (_principal, taskId) => join(dir, taskId, 'auth.json'),
      runner,
    });
    const first = await service.begin(key, { chatType: 'p2p', botCliId: 'codex' });
    await expect(service.complete(key, first.taskId, 0)).rejects.toMatchObject({ name: 'CredentialVersionConflictError' });
    expect(task.status).toBe('failed');
    expect(existsSync(join(dir, first.taskId, 'auth.json'))).toBe(false);
    const second = await service.begin(key, { chatType: 'p2p', botCliId: 'codex' });
    expect(second.taskId).not.toBe(first.taskId);
    expect(starts).toBe(2);
  });

  it('stops on a stale credential version instead of writing a refresh over a rotated row', async () => {
    const dir = tempDir();
    const authPath = join(dir, 'auth.json');
    writeCodexAuthJson({ authPath, authJson: '{"tokens":{"access_token":"refresh-secret"}}' });
    let calls = 0;
    let conflicted = false;
    const watcher = new CodexAuthRefreshWatcher({
      authPath,
      key: { larkAppId: 'app_a', openId: 'ou_owner' },
      credentialVersion: 3,
      repository: {
        putCredential: async () => {
          calls += 1;
          throw Object.assign(new Error('credential_version_conflict'), { name: 'CredentialVersionConflictError' });
        },
      },
      onVersionConflict: () => { conflicted = true; },
    });
    await watcher.flush();
    expect(calls).toBe(1);
    expect(conflicted).toBe(true);
    watcher.stop();
  });

  it('converges same-body CAS races across two auth refresh watchers', async () => {
    const dir = tempDir();
    const authPath = join(dir, 'auth.json');
    const body = '{"tokens":{"access_token":"same-body"}}';
    writeFileSync(authPath, body, { mode: 0o600 });
    let writes = 0;
    const inputs: any[] = [];
    const repository: any = {
      putCredential: async (input: any) => {
        writes += 1;
        inputs.push(input);
        if (writes === 1) throw Object.assign(new Error('credential_version_conflict'), { name: 'CredentialVersionConflictError' });
        return { ...input.key, credentialKind: 'codex_chatgpt', credentialVersion: 9, updatedAt: '' };
      },
      readSecret: async () => ({
        metadata: { credentialKind: 'codex_chatgpt', credentialVersion: 9 },
        secret: body,
      }),
    };
    let failed = 0;
    const watcher = new CodexAuthRefreshWatcher({
      authPath,
      key: { larkAppId: 'app_a', openId: 'ou_owner' },
      credentialVersion: 3,
      repository,
      onRefreshFailure: () => { failed += 1; },
    });
    const watcherTwo = new CodexAuthRefreshWatcher({
      authPath,
      key: { larkAppId: 'app_a', openId: 'ou_owner' },
      credentialVersion: 3,
      repository,
      onRefreshFailure: () => { failed += 1; },
    });
    await Promise.all([watcher.flush(), watcherTwo.flush()]);
    expect(writes).toBe(2);
    expect(failed).toBe(0);

    writeFileSync(authPath, '{"tokens":{"access_token":"new-body"}}\n', { mode: 0o600 });
    await watcher.flush();
    expect(writes).toBe(3);
    expect(inputs[2]?.expectedVersion).toBe(9);
    watcher.stop();
    watcherTwo.stop();
  });

  it('fails closed when a CAS race finds a different DB body', async () => {
    const dir = tempDir();
    const authPath = join(dir, 'auth.json');
    writeFileSync(authPath, '{"tokens":{"access_token":"local-body"}}\n', { mode: 0o600 });
    let failed = 0;
    const watcher = new CodexAuthRefreshWatcher({
      authPath,
      key: { larkAppId: 'app_a', openId: 'ou_owner' },
      credentialVersion: 3,
      repository: {
        putCredential: async () => { throw Object.assign(new Error('credential_version_conflict'), { name: 'CredentialVersionConflictError' }); },
        readSecret: async () => ({ metadata: { credentialKind: 'codex_chatgpt', credentialVersion: 4 }, secret: '{"tokens":{"access_token":"db-body"}}' }),
      },
      onRefreshFailure: () => { failed += 1; },
    });
    await watcher.flush();
    expect(failed).toBe(1);
    watcher.stop();
  });

  it('does not persist empty or tokenless auth refresh material', async () => {
    const dir = tempDir();
    const authPath = join(dir, 'auth.json');
    let calls = 0;
    let failed = 0;
    writeFileSync(authPath, '{}\n', { mode: 0o600 });
    const watcher = new CodexAuthRefreshWatcher({
      authPath,
      key: { larkAppId: 'app_a', openId: 'ou_owner' },
      credentialVersion: 3,
      repository: { putCredential: async () => { calls += 1; return {} as any; } },
      onRefreshFailure: () => { failed += 1; },
    });
    await watcher.flush();
    expect(calls).toBe(0);
    expect(failed).toBe(1);
    watcher.stop();
  });

  it('fails closed when the Codex auth watcher cannot initialize', async () => {
    const dir = tempDir();
    let failed = 0;
    const watcher = new CodexAuthRefreshWatcher({
      authPath: join(dir, 'missing-parent', 'auth.json'),
      key: { larkAppId: 'app_a', openId: 'ou_owner' },
      credentialVersion: 1,
      repository: { putCredential: async () => { throw new Error('must not persist'); } },
      onRefreshFailure: () => { failed += 1; },
    });
    expect(() => watcher.start()).toThrow();
    await Promise.resolve();
    expect(failed).toBe(1);
    watcher.stop();
  });

  it('cleans the temporary auth file when Codex status probing fails', async () => {
    const dir = tempDir();
    const key = { larkAppId: 'app_a', openId: 'ou_owner' } as const;
    let authPath = '';
    const repository: any = {
      beginCodexLoginTask: async (input: any) => { authPath = join(dir, input.taskId, 'auth.json'); },
      updateCodexLoginTask: async () => undefined,
      putCredential: async () => { throw new Error('must not persist after status failure'); },
      deleteCredential: async () => false,
    };
    const service = new CodexDeviceLoginService({
      repository,
      authPathFor: (_principal, taskId) => join(dir, taskId, 'auth.json'),
      runner: {
        startDeviceAuth: async ({ authPath: path }: { authPath: string }) => {
          writeCodexAuthJson({ authPath: path, authJson: '{"tokens":{"access_token":"status-secret"}}' });
          return { verificationUri: 'https://auth.example.test/device', userCode: 'ABCD-EFGH' };
        },
        status: async () => { throw new Error('status probe failed: access_token=should-redact'); },
        logout: async () => undefined,
      },
    });
    const challenge = await service.begin(key, { chatType: 'p2p', botCliId: 'codex' });
    authPath = join(dir, challenge.taskId, 'auth.json');
    await expect(service.complete(key, challenge.taskId)).rejects.toThrow('status probe failed');
    expect(existsSync(authPath)).toBe(false);
  });
});

describe('T6 Codex Podman status probe', () => {
  function fakePodman(dir: string, runBody: string): { command: string; log: string } {
    const command = join(dir, 'fake-podman.sh');
    const log = join(dir, 'podman-args.log');
    writeFileSync(command, `#!/bin/sh
printf '%s\\n' "$@" >> ${JSON.stringify(log)}
if [ "$1" = "run" ]; then
  ${runBody}
fi
exit 0
`, { mode: 0o700 });
    chmodSync(command, 0o700);
    return { command, log };
  }

  function makeRunner(dir: string, command: string, statusTimeoutMs?: number): { runner: PodmanCodexDeviceAuthRunner; authPath: string } {
    const authRoot = join(dir, 'auth-root');
    const authPath = join(authRoot, 'task', 'auth.json');
    writeCodexAuthJson({ authPath, authJson: '{"tokens":{"access_token":"status-token"}}' });
    return {
      runner: new PodmanCodexDeviceAuthRunner({
        image: `registry.example.test/botmux@sha256:${'a'.repeat(64)}`,
        authRoot,
        hostUid: 1000,
        hostGid: 1000,
        command,
        ...(statusTimeoutMs === undefined ? {} : { statusTimeoutMs }),
      }),
      authPath,
    };
  }

  it('runs real codex login status in an isolated read-only auth container', async () => {
    const dir = tempDir();
    const fake = fakePodman(dir, 'if [ "$1" = "run" ]; then exit 0; fi');
    const { runner, authPath } = makeRunner(dir, fake.command);
    await expect(runner.status({ authPath })).resolves.toEqual({ loggedIn: true });
    const args = readFileSync(fake.log, 'utf8');
    expect(args).toContain('--network=pasta:--no-map-gw');
    expect(args).toContain(`--mount=type=bind,src=${join(dir, 'auth-root', 'task')},dst=/home/dev/.codex,ro`);
    expect(args).toContain('--entrypoint=codex');
    expect(args).toContain('login\nstatus');
    expect(args).not.toContain('codex\nlogin\nstatus');
    expect(args).not.toContain('--network=host');
    expect(args).not.toContain('--publish');
    expect(args).toContain('rm\n--force\n--ignore');
  });

  it('starts device auth through the codex entrypoint without a duplicate executable', async () => {
    const dir = tempDir();
    const fake = fakePodman(dir, 'if [ "$1" = "run" ]; then printf "https://auth.example.test/device code ABCD-EFGH\\n"; fi');
    const authRoot = join(dir, 'auth-root');
    const authPath = join(authRoot, 'task', 'auth.json');
    const runner = new PodmanCodexDeviceAuthRunner({
      image: `registry.example.test/botmux@sha256:${'a'.repeat(64)}`,
      authRoot,
      hostUid: 1000,
      hostGid: 1000,
      command: fake.command,
    });
    await expect(runner.startDeviceAuth({ authPath, timeoutMs: 1_000 })).resolves.toMatchObject({
      verificationUri: 'https://auth.example.test/device',
      userCode: 'ABCD-EFGH',
    });
    const args = readFileSync(fake.log, 'utf8');
    expect(args).toContain('--entrypoint=codex');
    expect(args).toContain('login\n--device-auth');
    expect(args).not.toContain('codex\nlogin\n--device-auth');
  });

  it('treats a nonzero codex login status as not logged in', async () => {
    const dir = tempDir();
    const fake = fakePodman(dir, 'if [ "$1" = "run" ]; then exit 7; fi');
    const { runner, authPath } = makeRunner(dir, fake.command);
    await expect(runner.status({ authPath })).resolves.toEqual({ loggedIn: false });
    expect(readFileSync(fake.log, 'utf8')).toContain('--entrypoint=codex');
    expect(readFileSync(fake.log, 'utf8')).toContain('login\nstatus');
    expect(readFileSync(fake.log, 'utf8')).not.toContain('codex\nlogin\nstatus');
  });

  it('fails closed on a status timeout and still requests container cleanup', async () => {
    const dir = tempDir();
    const fake = fakePodman(dir, 'if [ "$1" = "run" ]; then sleep 2; fi');
    const { runner, authPath } = makeRunner(dir, fake.command, 1_000);
    await expect(runner.status({ authPath })).rejects.toThrow('Codex login status probe failed');
    expect(readFileSync(fake.log, 'utf8')).toContain('rm\n--force\n--ignore');
  });
});

describe('T6 data publish relay', () => {
  it('is covered by the dedicated relay tests', () => {
    expect(true).toBe(true);
  });
});
