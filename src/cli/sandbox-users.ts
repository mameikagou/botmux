import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { parse as parseDotenv } from 'dotenv';

import { resolveBotsConfigFile } from '../core/config-dir.js';
import {
  sandboxUserHashForId,
  sandboxUserPodName,
} from '../execution/podman-user-pod.js';
import {
  applyAgentPrincipalMigration,
  createAgentPrincipalPool,
} from '../services/agent-principal-store.js';
import {
  applySandboxUserRegistryMigration,
  SandboxUserRegistryRepository,
  type SandboxUserIdentityRow,
  type SandboxUserRow,
} from '../services/sandbox-user-registry.js';
import { updateBotsJsonAtomic } from '../setup/bots-store.js';

const USAGE = `usage:
  botmux sandbox-user add <user-id> [--native] [--disabled] [--can-openmemory] [--json]
  botmux sandbox-user bind <user-id> --app-id <cli_xxx> --open-id <ou_xxx> [--no-grant] [--json]
  botmux sandbox-user list [--json]
  botmux sandbox-user enable|disable <user-id> [--json]
  botmux sandbox-user pods [--json]

Database resolution: --database-url, BOTMUX_AGENT_DATABASE_URL, then ~/.botmux/.env.`;

type AdminRepository = Pick<
  SandboxUserRegistryRepository,
  'bindIdentity' | 'createUser' | 'getUser' | 'listIdentities' | 'listUsers' | 'setUserEnabled'
>;

interface PodSummary {
  readonly userId: string;
  readonly generation: number;
  readonly podName: string;
  readonly status: string;
}

export interface SandboxUserCommandContext {
  readonly repository: AdminRepository;
  readonly close: () => Promise<void>;
  readonly grantAllowedUser: (appId: string, openId: string) => boolean;
  readonly inspectPods: (users: readonly SandboxUserRow[]) => readonly PodSummary[];
  readonly stopPod: (user: SandboxUserRow) => void;
  readonly stdout: (value: string) => void;
}

function valueAfter(args: readonly string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
}

function requiredId(args: readonly string[]): string {
  const value = args[1]?.trim();
  if (!value || value.startsWith('-') || /[\u0000\r\n]/u.test(value)) throw new Error(USAGE);
  return value;
}

function requiredFlag(args: readonly string[], flag: string): string {
  const value = valueAfter(args, flag)?.trim();
  if (!value || value.startsWith('-') || /[\u0000\r\n]/u.test(value)) throw new Error(`${flag} is required\n${USAGE}`);
  return value;
}

function databaseUrl(args: readonly string[]): string | undefined {
  const explicit = valueAfter(args, '--database-url')?.trim();
  if (explicit) return explicit;
  const ambient = process.env.BOTMUX_AGENT_DATABASE_URL?.trim()
    || process.env.QRANT_RESEARCH_DATABASE_URL?.trim();
  if (ambient) return ambient;
  const envPath = join(homedir(), '.botmux', '.env');
  if (!existsSync(envPath)) return undefined;
  const parsed = parseDotenv(readFileSync(envPath));
  return parsed.BOTMUX_AGENT_DATABASE_URL?.trim()
    || parsed.QRANT_RESEARCH_DATABASE_URL?.trim();
}

function podmanRows(): Array<Record<string, unknown>> {
  const result = spawnSync('podman', ['pod', 'ps', '--format=json'], {
    encoding: 'utf8',
    shell: false,
    timeout: 10_000,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`podman pod ps failed: ${result.stderr.trim() || `exit ${String(result.status)}`}`);
  const parsed: unknown = JSON.parse(result.stdout || '[]');
  if (!Array.isArray(parsed)) throw new Error('podman pod ps returned an invalid response');
  return parsed.filter((row): row is Record<string, unknown> => !!row && typeof row === 'object' && !Array.isArray(row));
}

function inspectPods(users: readonly SandboxUserRow[]): readonly PodSummary[] {
  const byName = new Map<string, Record<string, unknown>>();
  for (const row of podmanRows()) {
    const name = typeof row.Name === 'string' ? row.Name : typeof row.name === 'string' ? row.name : undefined;
    if (name) byName.set(name, row);
  }
  return users.map(user => {
    const hash = sandboxUserHashForId(user.sandboxUserId);
    const podName = sandboxUserPodName(hash, user.podGeneration);
    const row = byName.get(podName);
    const status = row
      ? String(row.Status ?? row.status ?? row.State ?? row.state ?? 'unknown')
      : 'missing';
    return { userId: user.sandboxUserId, generation: user.podGeneration, podName, status };
  });
}

function stopPod(user: SandboxUserRow): void {
  const hash = sandboxUserHashForId(user.sandboxUserId);
  const podName = sandboxUserPodName(hash, user.podGeneration);
  const inspect = spawnSync('podman', ['pod', 'inspect', '--format={{json .Labels}}', podName], {
    encoding: 'utf8', shell: false, timeout: 10_000,
  });
  if (inspect.status !== 0) return;
  const labels = JSON.parse(inspect.stdout || '{}') as Record<string, unknown>;
  if (labels['io.botmux.managed'] !== 'true'
    || labels['io.botmux.sandbox-user-hash'] !== hash
    || labels['io.botmux.pod-generation'] !== String(user.podGeneration)) {
    throw new Error(`refusing to stop unverified pod ${podName}`);
  }
  const stopped = spawnSync('podman', ['pod', 'stop', '--time', '10', podName], {
    encoding: 'utf8', shell: false, timeout: 30_000,
  });
  if (stopped.status !== 0 && !/no such pod|not found/iu.test(stopped.stderr)) {
    throw new Error(`could not stop ${podName}: ${stopped.stderr.trim() || `exit ${String(stopped.status)}`}`);
  }
}

async function defaultContext(args: readonly string[]): Promise<SandboxUserCommandContext> {
  const pool = createAgentPrincipalPool(databaseUrl(args));
  await applyAgentPrincipalMigration(pool);
  await applySandboxUserRegistryMigration(pool);
  const botsPath = resolveBotsConfigFile();
  return {
    repository: new SandboxUserRegistryRepository(pool),
    close: async () => { await pool.end?.(); },
    grantAllowedUser: (appId, openId) => {
      let changed = false;
      updateBotsJsonAtomic(botsPath, bots => {
        const matches = bots.filter(bot => bot && typeof bot === 'object' && bot.larkAppId === appId);
        if (matches.length !== 1) throw new Error(`bots.json must contain exactly one bot for ${appId}`);
        const bot = matches[0] as Record<string, unknown>;
        const current = Array.isArray(bot.allowedUsers) ? bot.allowedUsers.map(String) : [];
        if (current.includes(openId)) return bots;
        bot.allowedUsers = [...current, openId];
        changed = true;
        return bots;
      });
      return changed;
    },
    inspectPods,
    stopPod,
    stdout: value => process.stdout.write(value),
  };
}

function identityMap(identities: readonly SandboxUserIdentityRow[]): Map<string, SandboxUserIdentityRow[]> {
  const result = new Map<string, SandboxUserIdentityRow[]>();
  for (const identity of identities) {
    const rows = result.get(identity.sandboxUserId) ?? [];
    rows.push(identity);
    result.set(identity.sandboxUserId, rows);
  }
  return result;
}

function output(context: SandboxUserCommandContext, value: unknown, json: boolean): void {
  if (json) {
    context.stdout(`${JSON.stringify(value, null, 2)}\n`);
    return;
  }
  if (Array.isArray(value)) {
    for (const row of value as Array<Record<string, unknown>>) {
      context.stdout(`${Object.values(row).join('\t')}\n`);
    }
    return;
  }
  context.stdout(`${JSON.stringify(value)}\n`);
}

export async function runSandboxUserCommand(
  args: readonly string[],
  injected?: SandboxUserCommandContext,
): Promise<void> {
  const action = args[0] ?? 'help';
  if (action === 'help' || action === '--help' || action === '-h') {
    (injected?.stdout ?? (value => process.stdout.write(value)))(`${USAGE}\n`);
    return;
  }
  const context = injected ?? await defaultContext(args);
  const json = args.includes('--json');
  try {
    if (action === 'add') {
      const userId = requiredId(args);
      if (args.includes('--native') && args.includes('--podman')) throw new Error('choose only one of --native or --podman');
      if (args.includes('--can-openmemory') && !args.includes('--native')) {
        throw new Error('--can-openmemory is only valid for an explicitly native user');
      }
      if (await context.repository.getUser({ sandboxUserId: userId })) {
        throw new Error(`sandbox user already exists: ${userId}; use enable or bind instead`);
      }
      const user = await context.repository.createUser({
        sandboxUserId: userId,
        enabled: !args.includes('--disabled'),
        canOpenMemory: args.includes('--can-openmemory'),
        executionMode: args.includes('--native') ? 'native' : 'podman',
      });
      output(context, user, json);
      return;
    }
    if (action === 'bind') {
      const userId = requiredId(args);
      const appId = requiredFlag(args, '--app-id');
      const openId = requiredFlag(args, '--open-id');
      const existing = await context.repository.getUser({ sandboxUserId: userId });
      if (!existing) throw new Error(`sandbox user is not registered: ${userId}`);
      const binding = await context.repository.bindIdentity({
        sandboxUserId: userId,
        key: { larkAppId: appId, openId },
      });
      const granted = args.includes('--no-grant') ? false : context.grantAllowedUser(appId, openId);
      output(context, { user: binding.user, identity: binding.identity, allowedUsersUpdated: granted }, json);
      return;
    }
    if (action === 'enable' || action === 'disable') {
      const userId = requiredId(args);
      const current = await context.repository.getUser({ sandboxUserId: userId });
      if (!current) throw new Error(`sandbox user is not registered: ${userId}`);
      const enabled = action === 'enable';
      const user = await context.repository.setUserEnabled({ sandboxUserId: userId }, enabled);
      if (!enabled) context.stopPod(current);
      output(context, user, json);
      return;
    }
    if (action === 'list') {
      const [users, identities] = await Promise.all([
        context.repository.listUsers(),
        context.repository.listIdentities(),
      ]);
      const byUser = identityMap(identities);
      const rows = users.map(user => ({
        userId: user.sandboxUserId,
        enabled: user.enabled,
        mode: user.executionMode,
        canOpenMemory: user.canOpenMemory,
        generation: user.podGeneration,
        identities: (byUser.get(user.sandboxUserId) ?? [])
          .map(identity => `${identity.larkAppId}:${identity.openId}${identity.enabled ? '' : ' (disabled)'}`)
          .join(','),
      }));
      output(context, rows, json);
      return;
    }
    if (action === 'pods') {
      const users = await context.repository.listUsers();
      output(context, context.inspectPods(users.filter(user => user.executionMode === 'podman')), json);
      return;
    }
    throw new Error(USAGE);
  } finally {
    if (!injected) await context.close();
  }
}

export { USAGE as SANDBOX_USER_COMMAND_USAGE };
