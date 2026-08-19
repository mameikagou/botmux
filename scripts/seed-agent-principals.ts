#!/usr/bin/env tsx
import { existsSync, readFileSync } from 'node:fs';
import { resolveBotsConfigFile } from '../src/core/config-dir.js';
import { applyAgentPrincipalMigration, AgentPrincipalRepository, createAgentPrincipalPool, rollbackAgentPrincipalMigration } from '../src/services/agent-principal-store.js';
import { buildPrincipalSeedRows, seedAgentPrincipals } from '../src/services/agent-principal-seed.js';
import type { AgentPrincipalKey } from '../src/services/agent-principal-store.js';

function value(args: readonly string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
}

function ownerMap(args: readonly string[]): Map<string, string> {
  const map = new Map<string, string>();
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] !== '--owner') continue;
    const raw = args[index + 1] ?? '';
    const split = raw.indexOf(':');
    if (split <= 0) throw new Error('--owner must be <larkAppId>:<app-scoped open_id>');
    const appId = raw.slice(0, split);
    const openId = raw.slice(split + 1);
    if (map.has(appId) && map.get(appId) !== openId) throw new Error(`duplicate conflicting --owner for ${appId}`);
    map.set(appId, openId);
  }
  return map;
}

function explicitUsers(args: readonly string[]): { mappings: Map<string, string>; principals: AgentPrincipalKey[] } {
  const mappings = new Map<string, string>();
  const principals: AgentPrincipalKey[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    if (flag !== '--map' && flag !== '--open-id' && flag !== '--principal') continue;
    const raw = args[index + 1] ?? '';
    if (flag === '--map') {
      const equals = raw.indexOf('=');
      const split = raw.indexOf(':');
      if (split <= 0 || equals <= split + 1 || equals === raw.length - 1) throw new Error('--map must be <larkAppId>:<config-user>=<app-scoped open_id>');
      const key = `${raw.slice(0, split)}\0${raw.slice(split + 1, equals)}`;
      const openId = raw.slice(equals + 1);
      if (mappings.has(key) && mappings.get(key) !== openId) throw new Error(`conflicting --map for ${key.replace('\0', ':')}`);
      mappings.set(key, openId);
    } else {
      const split = raw.indexOf(':');
      if (split <= 0 || split === raw.length - 1) throw new Error(`${flag} must be <larkAppId>:<app-scoped open_id>`);
      principals.push({ larkAppId: raw.slice(0, split), openId: raw.slice(split + 1) });
    }
  }
  return { mappings, principals };
}

const args = process.argv.slice(2);
if ((args[0] ?? 'seed') === 'rollback') {
  const dryRun = !args.includes('--commit');
  process.stdout.write(JSON.stringify({ dryRun, action: 'rollback' }) + '\n');
  if (!dryRun) {
    const pool = createAgentPrincipalPool(value(args, '--database-url'));
    try { await rollbackAgentPrincipalMigration(pool); } finally { await pool.end?.(); }
  }
  process.exit(0);
}
const configPath = value(args, '--bots-config') ?? resolveBotsConfigFile();
const dryRun = !args.includes('--commit');
if (!existsSync(configPath)) throw new Error(`bots config does not exist: ${configPath}`);
const parsed = JSON.parse(readFileSync(configPath, 'utf8')) as unknown;
if (!Array.isArray(parsed)) throw new Error('bots config must be a JSON array');
const bots = parsed.map((raw, index) => {
  if (!raw || typeof raw !== 'object') throw new Error(`bot config ${index} is invalid`);
  const entry = raw as Record<string, unknown>;
  return { larkAppId: String(entry.larkAppId ?? ''), allowedUsers: Array.isArray(entry.allowedUsers) ? entry.allowedUsers.map(String) : [] };
});
const explicit = explicitUsers(args);
const rows = buildPrincipalSeedRows({ bots, ownerOpenIds: ownerMap(args), userOpenIdMappings: explicit.mappings, explicitOpenIds: explicit.principals });
process.stdout.write(JSON.stringify({ dryRun, configPath, principals: rows }, null, 2) + '\n');
if (!dryRun) {
  const pool = createAgentPrincipalPool(value(args, '--database-url'));
  await applyAgentPrincipalMigration(pool);
  const result = await seedAgentPrincipals({ repository: new AgentPrincipalRepository(pool), rows, dryRun: false });
  process.stdout.write(JSON.stringify({ persisted: result.persisted?.map(row => ({ larkAppId: row.larkAppId, openId: row.openId, enabled: row.enabled, canOpenMemory: row.canOpenMemory })) }, null, 2) + '\n');
  await pool.end?.();
}
