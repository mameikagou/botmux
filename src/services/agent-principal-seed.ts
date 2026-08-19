import type { AgentPrincipalKey, AgentPrincipalRepository, AgentPrincipalRow } from './agent-principal-store.js';

export interface SeedBotConfig {
  readonly larkAppId: string;
  readonly allowedUsers?: readonly string[];
}

export interface SeedPrincipalRow {
  readonly key: AgentPrincipalKey;
  readonly canOpenMemory: boolean;
  readonly reason: 'allowed_user' | 'explicit_owner';
}

function validOpenId(value: string): boolean { return /^ou_[A-Za-z0-9]+$/u.test(value); }

/**
 * Build a strict seed list from the exact app-scoped IDs already in bots.json.
 * No union/contact lookup is attempted. Owner OpenIDs must be supplied
 * explicitly per app; guessing the first allowed user would grant MemoryGate
 * to the wrong person.
 */
export function buildPrincipalSeedRows(input: {
  readonly bots: readonly SeedBotConfig[];
  readonly ownerOpenIds: ReadonlyMap<string, string>;
  /** Explicit `app:raw-config-value=ou_xxx` mappings for legacy email lists. */
  readonly userOpenIdMappings?: ReadonlyMap<string, string>;
  /** Extra app-scoped IDs supplied explicitly when the config does not carry
   * the exact open_id string (never inferred from contact APIs). */
  readonly explicitOpenIds?: ReadonlyArray<AgentPrincipalKey>;
}): SeedPrincipalRow[] {
  const rows: SeedPrincipalRow[] = [];
  const seen = new Set<string>();
  const configuredApps = new Set(input.bots.map(bot => bot.larkAppId.trim()).filter(Boolean));
  for (const bot of input.bots) {
    if (typeof bot.larkAppId !== 'string' || bot.larkAppId.trim() === '') throw new Error('bot config has no larkAppId');
    const appId = bot.larkAppId.trim();
    const owner = input.ownerOpenIds.get(appId);
    if (!owner || !validOpenId(owner)) throw new Error(`missing explicit --owner ${appId}:ou_... mapping`);
    const users = [...(bot.allowedUsers ?? [])];
    for (const raw of users) {
      const mapped = validOpenId(raw)
        ? raw
        : input.userOpenIdMappings?.get(`${appId}\0${raw}`);
      if (!mapped || !validOpenId(mapped)) {
        throw new Error(`allowedUsers for ${appId} contains an unresolved identity; provide an explicit --map ${appId}:${raw}=ou_...`);
      }
      const key = { larkAppId: appId, openId: mapped };
      const dedupe = `${appId}\0${mapped}`;
      if (seen.has(dedupe)) continue;
      seen.add(dedupe);
      rows.push({ key, canOpenMemory: mapped === owner, reason: mapped === owner ? 'explicit_owner' : 'allowed_user' });
    }
    const ownerKey = `${appId}\0${owner}`;
    if (!seen.has(ownerKey)) {
      seen.add(ownerKey);
      rows.push({ key: { larkAppId: appId, openId: owner }, canOpenMemory: true, reason: 'explicit_owner' });
    }
  }
  for (const key of input.explicitOpenIds ?? []) {
    if (typeof key.larkAppId !== 'string' || typeof key.openId !== 'string' || !validOpenId(key.openId)) {
      throw new Error('explicit principal must be <larkAppId>:<app-scoped ou_...>');
    }
    if (!configuredApps.has(key.larkAppId.trim())) throw new Error(`explicit principal app is absent from bots config: ${key.larkAppId}`);
    const dedupe = `${key.larkAppId}\0${key.openId}`;
    if (seen.has(dedupe)) continue;
    seen.add(dedupe);
    rows.push({ key, canOpenMemory: input.ownerOpenIds.get(key.larkAppId) === key.openId, reason: input.ownerOpenIds.get(key.larkAppId) === key.openId ? 'explicit_owner' : 'allowed_user' });
  }
  return rows;
}

export async function seedAgentPrincipals(input: {
  readonly repository: Pick<AgentPrincipalRepository, 'seedPrincipals'>;
  readonly rows: readonly SeedPrincipalRow[];
  readonly dryRun: boolean;
}): Promise<{ readonly rows: SeedPrincipalRow[]; readonly persisted?: AgentPrincipalRow[] }> {
  if (input.dryRun) return { rows: [...input.rows] };
  const persisted = await input.repository.seedPrincipals(input.rows.map(row => ({ key: row.key, canOpenMemory: row.canOpenMemory, enabled: true })));
  return { rows: [...input.rows], persisted };
}
