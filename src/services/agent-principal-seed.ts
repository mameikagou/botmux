import type { AgentExecutionMode, AgentPrincipalKey, AgentPrincipalRepository, AgentPrincipalRow } from './agent-principal-store.js';

export interface SeedBotConfig {
  readonly larkAppId: string;
  readonly allowedUsers?: readonly string[];
}

export interface SeedPrincipalRow {
  readonly key: AgentPrincipalKey;
  readonly canOpenMemory: boolean;
  readonly executionMode?: AgentExecutionMode;
  readonly reason: 'allowed_user' | 'explicit_owner';
}

function validOpenId(value: string): boolean { return /^ou_[A-Za-z0-9]+$/u.test(value); }

const MAPPING_SEPARATOR = '\0';

function mappingError(message: string): never {
  throw new Error(`invalid --map mapping: ${message}`);
}

/**
 * Validate the internal composite mapping key before any row is built.  The
 * CLI turns `app:raw` into `app\0raw`; keeping that representation exact is
 * important because a mapping must apply to one app and one raw config value,
 * not to every app that happens to contain the same value.
 */
function validateUserOpenIdMappings(
  mappings: ReadonlyMap<string, string> | undefined,
  configuredApps: ReadonlySet<string>,
): Map<string, string> {
  const validated = new Map<string, string>();
  for (const [key, mapped] of mappings ?? []) {
    if (typeof key !== 'string') mappingError('key must be <larkAppId>\\0<raw-config-value>');
    if (typeof mapped !== 'string' || !validOpenId(mapped)) {
      mappingError('target must be an app-scoped open_id (ou_...)');
    }
    const split = key.indexOf(MAPPING_SEPARATOR);
    if (split <= 0 || split !== key.lastIndexOf(MAPPING_SEPARATOR) || split === key.length - 1) {
      mappingError('key must be <larkAppId>\\0<non-empty raw-config-value>');
    }
    const appId = key.slice(0, split);
    const raw = key.slice(split + 1);
    if (appId.trim() !== appId || appId === '') mappingError('key contains an invalid app id');
    if (raw.trim() === '') mappingError('raw config value must not be empty');
    if (!configuredApps.has(appId)) {
      mappingError(`app is absent from bots config: ${appId}`);
    }
    const existing = validated.get(key);
    if (existing !== undefined && existing !== mapped) {
      mappingError(`conflicting values for ${appId}:${raw}`);
    }
    validated.set(key, mapped);
  }
  return validated;
}

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
  const configuredApps = new Set<string>();
  for (const bot of input.bots) {
    if (typeof bot.larkAppId !== 'string' || bot.larkAppId.trim() === '') throw new Error('bot config has no larkAppId');
    configuredApps.add(bot.larkAppId.trim());
  }
  const mappings = validateUserOpenIdMappings(input.userOpenIdMappings, configuredApps);
  const consumedMappings = new Set<string>();
  for (const bot of input.bots) {
    const appId = bot.larkAppId.trim();
    const owner = input.ownerOpenIds.get(appId);
    if (!owner || !validOpenId(owner)) throw new Error(`missing explicit --owner ${appId}:ou_... mapping`);
    const users = [...(bot.allowedUsers ?? [])];
    for (const raw of users) {
      if (typeof raw !== 'string') {
        throw new Error(`allowedUsers for ${appId} contains an unresolved identity; provide an explicit --map ${appId}:<raw>=ou_...`);
      }
      const mappingKey = `${appId}${MAPPING_SEPARATOR}${raw}`;
      const hasMapping = mappings.has(mappingKey);
      if (hasMapping) consumedMappings.add(mappingKey);
      // An explicit mapping wins even when the raw config value already looks
      // like an open_id: copied ou_ values are syntactically valid but may be
      // scoped to another Lark app.
      const mapped = hasMapping ? mappings.get(mappingKey) : (validOpenId(raw) ? raw : undefined);
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
  for (const key of mappings.keys()) {
    if (!consumedMappings.has(key)) {
      const split = key.indexOf(MAPPING_SEPARATOR);
      throw new Error(`unused --map mapping for ${key.slice(0, split)}:${key.slice(split + 1)}`);
    }
  }
  for (const key of input.explicitOpenIds ?? []) {
    if (typeof key?.larkAppId !== 'string' || typeof key.openId !== 'string' || !validOpenId(key.openId)) {
      throw new Error('explicit principal must be <larkAppId>:<app-scoped ou_...>');
    }
    const appId = key.larkAppId.trim();
    if (appId === '' || appId !== key.larkAppId) {
      throw new Error('explicit principal must use the exact configured larkAppId');
    }
    if (!configuredApps.has(appId)) throw new Error(`explicit principal app is absent from bots config: ${appId}`);
    const dedupe = `${appId}\0${key.openId}`;
    if (seen.has(dedupe)) continue;
    seen.add(dedupe);
    const canOpenMemory = input.ownerOpenIds.get(appId) === key.openId;
    rows.push({ key: { larkAppId: appId, openId: key.openId }, canOpenMemory, reason: canOpenMemory ? 'explicit_owner' : 'allowed_user' });
  }
  return rows;
}

export async function seedAgentPrincipals(input: {
  readonly repository: Pick<AgentPrincipalRepository, 'seedPrincipals'>;
  readonly rows: readonly SeedPrincipalRow[];
  readonly dryRun: boolean;
}): Promise<{ readonly rows: SeedPrincipalRow[]; readonly persisted?: AgentPrincipalRow[] }> {
  if (input.dryRun) return { rows: [...input.rows] };
  const persisted = await input.repository.seedPrincipals(input.rows.map(row => ({
    key: row.key,
    canOpenMemory: row.canOpenMemory,
    enabled: true,
    ...(row.executionMode ? { executionMode: row.executionMode } : {}),
  })));
  return { rows: [...input.rows], persisted };
}
