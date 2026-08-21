import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  runSandboxUserCommand,
  type SandboxUserCommandContext,
} from '../src/cli/sandbox-users.js';
import type {
  SandboxUserIdentityRow,
  SandboxUserRow,
} from '../src/services/sandbox-user-registry.js';

function row(id: string, overrides: Partial<SandboxUserRow> = {}): SandboxUserRow {
  return {
    sandboxUserId: id,
    enabled: true,
    canOpenMemory: false,
    executionMode: 'podman',
    podGeneration: 1,
    createdAt: '2026-08-21T00:00:00.000Z',
    updatedAt: '2026-08-21T00:00:00.000Z',
    ...overrides,
  };
}

function context(): SandboxUserCommandContext & {
  users: Map<string, SandboxUserRow>;
  identities: SandboxUserIdentityRow[];
  bots: any[];
  output: string[];
} {
  const users = new Map<string, SandboxUserRow>();
  const identities: SandboxUserIdentityRow[] = [];
  const bots = [{ name: 'deepwork', larkAppId: 'cli_deep', allowedUsers: ['ou_owner'] }];
  const output: string[] = [];
  return {
    users,
    identities,
    bots,
    output,
    repository: {
      async createUser(input) {
        const created = row(input.sandboxUserId ?? 'generated', {
          enabled: input.enabled ?? true,
          canOpenMemory: input.canOpenMemory ?? false,
          executionMode: input.executionMode ?? 'podman',
        });
        users.set(created.sandboxUserId, created);
        return created;
      },
      async getUser(key) { return users.get(key.sandboxUserId); },
      async bindIdentity(input) {
        const user = users.get(input.sandboxUserId ?? '')!;
        const identity: SandboxUserIdentityRow = {
          sandboxUserId: user.sandboxUserId,
          larkAppId: input.key.larkAppId,
          openId: input.key.openId,
          enabled: input.enabled ?? true,
          createdAt: '2026-08-21T00:00:00.000Z',
          updatedAt: '2026-08-21T00:00:00.000Z',
        };
        identities.push(identity);
        return { user, identity, migratedCredential: false };
      },
      async listUsers() { return [...users.values()]; },
      async listIdentities() { return identities; },
      async setUserEnabled(key, enabled) {
        const current = users.get(key.sandboxUserId)!;
        const updated = row(current.sandboxUserId, {
          ...current,
          enabled,
          podGeneration: current.enabled === enabled ? current.podGeneration : current.podGeneration + 1,
        });
        users.set(updated.sandboxUserId, updated);
        return updated;
      },
    },
    close: vi.fn(async () => undefined),
    grantAllowedUser: vi.fn((appId, openId) => {
      const bot = bots.find(candidate => candidate.larkAppId === appId);
      if (!bot) throw new Error(`missing bot ${appId}`);
      if (bot.allowedUsers.includes(openId)) return false;
      bot.allowedUsers.push(openId);
      return true;
    }),
    inspectPods: listed => listed.map(user => ({
      userId: user.sandboxUserId,
      generation: user.podGeneration,
      podName: `pod-${user.sandboxUserId}`,
      status: 'Exited',
    })),
    stopPod: vi.fn(),
    stdout: value => output.push(value),
  };
}

describe('sandbox-user admin CLI', () => {
  let ctx: ReturnType<typeof context>;

  beforeEach(() => { ctx = context(); });

  it('adds arbitrary guest users without a hard-coded seed list', async () => {
    await runSandboxUserCommand(['add', 'guest-four', '--json'], ctx);
    expect(ctx.users.get('guest-four')).toMatchObject({
      enabled: true,
      executionMode: 'podman',
      canOpenMemory: false,
    });
  });

  it('refuses accidental re-enable through add and guest OpenMemory grants', async () => {
    ctx.users.set('guest-four', row('guest-four', { enabled: false }));
    await expect(runSandboxUserCommand(['add', 'guest-four'], ctx))
      .rejects.toThrow(/already exists/);
    await expect(runSandboxUserCommand(['add', 'guest-five', '--can-openmemory'], ctx))
      .rejects.toThrow(/explicitly native/);
  });

  it('binds the exact app-scoped identity and grants that bot allowedUsers', async () => {
    ctx.users.set('guest-four', row('guest-four'));
    await runSandboxUserCommand([
      'bind', 'guest-four', '--app-id', 'cli_deep', '--open-id', 'ou_four', '--json',
    ], ctx);
    expect(ctx.identities).toContainEqual(expect.objectContaining({
      sandboxUserId: 'guest-four', larkAppId: 'cli_deep', openId: 'ou_four',
    }));
    expect(ctx.bots[0].allowedUsers).toEqual(['ou_owner', 'ou_four']);
    expect(ctx.grantAllowedUser).toHaveBeenCalledOnce();
  });

  it('does not grant bots.json when --no-grant is explicit', async () => {
    ctx.users.set('guest-four', row('guest-four'));
    await runSandboxUserCommand([
      'bind', 'guest-four', '--app-id', 'cli_deep', '--open-id', 'ou_four', '--no-grant',
    ], ctx);
    expect(ctx.bots[0].allowedUsers).toEqual(['ou_owner']);
    expect(ctx.grantAllowedUser).not.toHaveBeenCalled();
  });

  it('disables the old generation and stops only that verified user pod', async () => {
    const current = row('guest-four', { podGeneration: 7 });
    ctx.users.set(current.sandboxUserId, current);
    await runSandboxUserCommand(['disable', 'guest-four', '--json'], ctx);
    expect(ctx.users.get('guest-four')).toMatchObject({ enabled: false, podGeneration: 8 });
    expect(ctx.stopPod).toHaveBeenCalledWith(current);
  });

  it('lists identities and cold pod states', async () => {
    ctx.users.set('guest-four', row('guest-four'));
    ctx.identities.push({
      sandboxUserId: 'guest-four', larkAppId: 'cli_deep', openId: 'ou_four', enabled: true,
      createdAt: '2026-08-21T00:00:00.000Z', updatedAt: '2026-08-21T00:00:00.000Z',
    });
    await runSandboxUserCommand(['list', '--json'], ctx);
    await runSandboxUserCommand(['pods', '--json'], ctx);
    expect(ctx.output.join('')).toContain('cli_deep:ou_four');
    expect(ctx.output.join('')).toContain('Exited');
  });
});
