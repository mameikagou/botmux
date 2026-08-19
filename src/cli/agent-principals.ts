import { existsSync, readFileSync } from 'node:fs';
import { resolveBotsConfigFile } from '../core/config-dir.js';
import { applyAgentPrincipalMigration, AgentPrincipalRepository, createAgentPrincipalPool, rollbackAgentPrincipalMigration } from '../services/agent-principal-store.js';
import { buildPrincipalSeedRows, seedAgentPrincipals } from '../services/agent-principal-seed.js';
import type { AgentPrincipalKey } from '../services/agent-principal-store.js';

function flagValue(args: readonly string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

function parseOwners(args: readonly string[]): Map<string, string> {
  const owners = new Map<string, string>();
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] !== '--owner') continue;
    const value = args[i + 1] ?? '';
    const split = value.indexOf(':');
    if (split <= 0 || split === value.length - 1) throw new Error('--owner must be <larkAppId>:<app-scoped open_id>');
    const appId = value.slice(0, split);
    const openId = value.slice(split + 1);
    if (owners.has(appId) && owners.get(appId) !== openId) throw new Error(`conflicting --owner mappings for ${appId}`);
    owners.set(appId, openId);
  }
  return owners;
}

function parseExplicitUsers(args: readonly string[]): { mappings: Map<string, string>; principals: AgentPrincipalKey[] } {
  const mappings = new Map<string, string>();
  const principals: AgentPrincipalKey[] = [];
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] !== '--map' && args[i] !== '--open-id' && args[i] !== '--principal') continue;
    const value = args[i + 1] ?? '';
    if (args[i] === '--map') {
      const equals = value.indexOf('=');
      const split = value.indexOf(':');
      if (split <= 0 || equals <= split + 1 || equals === value.length - 1) {
        throw new Error('--map must be <larkAppId>:<config-user>=<app-scoped open_id>');
      }
      const appId = value.slice(0, split);
      const raw = value.slice(split + 1, equals);
      const openId = value.slice(equals + 1);
      const key = `${appId}\0${raw}`;
      if (mappings.has(key) && mappings.get(key) !== openId) throw new Error(`conflicting --map mappings for ${appId}:${raw}`);
      mappings.set(key, openId);
      continue;
    }
    const split = value.indexOf(':');
    if (split <= 0 || split === value.length - 1) throw new Error(`${args[i]} must be <larkAppId>:<app-scoped open_id>`);
    principals.push({ larkAppId: value.slice(0, split), openId: value.slice(split + 1) });
  }
  return { mappings, principals };
}

export async function runAgentPrincipalSeedCommand(args: readonly string[]): Promise<void> {
  const action = args[0] ?? 'seed';
  if (action === 'rollback') {
    const dryRun = !args.includes('--commit');
    process.stdout.write(JSON.stringify({ dryRun, action: 'rollback' }) + '\n');
    if (dryRun) return;
    const pool = createAgentPrincipalPool(flagValue(args, '--database-url'));
    try { await rollbackAgentPrincipalMigration(pool); }
    finally { await pool.end?.(); }
    return;
  }
  if (action !== 'seed') throw new Error('usage: botmux agent-principals seed [--owner app:ou_xxx] [--map app:user=ou_xxx] [--principal app:ou_xxx] [--commit]');
  const configPath = flagValue(args, '--bots-config') ?? resolveBotsConfigFile();
  if (!existsSync(configPath)) throw new Error(`bots config does not exist: ${configPath}`);
  const parsed = JSON.parse(readFileSync(configPath, 'utf8')) as unknown;
  if (!Array.isArray(parsed)) throw new Error('bots config must be a JSON array');
  const bots = parsed.map((raw, index) => {
    if (!raw || typeof raw !== 'object') throw new Error(`bot config ${index} is invalid`);
    const entry = raw as Record<string, unknown>;
    return {
      larkAppId: typeof entry.larkAppId === 'string' ? entry.larkAppId : '',
      allowedUsers: Array.isArray(entry.allowedUsers) ? entry.allowedUsers.map(String) : [],
    };
  });
  const explicit = parseExplicitUsers(args);
  const rows = buildPrincipalSeedRows({
    bots,
    ownerOpenIds: parseOwners(args),
    userOpenIdMappings: explicit.mappings,
    explicitOpenIds: explicit.principals,
  });
  const dryRun = !args.includes('--commit');
  process.stdout.write(JSON.stringify({ dryRun, configPath, principals: rows }, null, 2) + '\n');
  if (dryRun) return;
  const pool = createAgentPrincipalPool(flagValue(args, '--database-url'));
  try {
    await applyAgentPrincipalMigration(pool);
    const result = await seedAgentPrincipals({ repository: new AgentPrincipalRepository(pool), rows, dryRun: false });
    process.stdout.write(JSON.stringify({
      persisted: result.persisted?.map(row => ({
        larkAppId: row.larkAppId,
        openId: row.openId,
        enabled: row.enabled,
        canOpenMemory: row.canOpenMemory,
      })),
    }, null, 2) + '\n');
  } finally {
    await pool.end?.();
  }
}
