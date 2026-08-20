/**
 * Non-secret skill bindings for one app-scoped agent principal.
 *
 * Skill files are never copied into the principal table. The database stores
 * the exact skill name and directory that may be mounted for a new instance;
 * the runtime validates the directory again before exposing it to a worker.
 */
import { existsSync, lstatSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import type {
  AgentPrincipalKey,
  SqlExecutor,
  SqlPool,
  SqlTransaction,
} from './agent-principal-store.js';
import { AgentPrincipalLookupError } from './agent-principal-store.js';

/** Default review skills attached to every newly created instance. */
export const DEFAULT_PRINCIPAL_SKILL_NAMES = [
  'mainline-drift-audit',
  'sanity',
  'quant-ui-sync',
] as const;

export type DefaultPrincipalSkillName = (typeof DEFAULT_PRINCIPAL_SKILL_NAMES)[number];

/** The only non-secret skill material persisted into Session/init. */
export interface FrozenPrincipalSkillBinding {
  readonly name: string;
  /** Host directory containing this skill's SKILL.md. */
  readonly rootDir: string;
  readonly entrypoint: string;
  readonly version?: string;
  readonly checksum?: string;
}

export interface AgentPrincipalSkillRow extends AgentPrincipalKey {
  readonly name: string;
  readonly rootDir: string;
  readonly enabled: boolean;
  readonly priority: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

/** Independent migration so skill policy can evolve without rewriting principals. */
export const AGENT_PRINCIPAL_SKILLS_UP_SQL = `
CREATE TABLE IF NOT EXISTS agent_principal_skills (
  lark_app_id text NOT NULL,
  open_id text NOT NULL,
  skill_name text NOT NULL,
  skill_root text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  priority integer NOT NULL DEFAULT 100,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (lark_app_id, open_id, skill_name),
  FOREIGN KEY (lark_app_id, open_id)
    REFERENCES agent_principals (lark_app_id, open_id)
    ON UPDATE CASCADE ON DELETE CASCADE,
  CHECK (length(trim(skill_name)) > 0),
  CHECK (length(trim(skill_root)) > 0),
  CHECK (skill_root LIKE '/%' AND skill_root NOT LIKE '%..%'),
  CHECK (priority >= 0 AND priority <= 100000)
);
CREATE INDEX IF NOT EXISTS agent_principal_skills_order_idx
  ON agent_principal_skills (lark_app_id, open_id, enabled, priority, skill_name);
`;

export const AGENT_PRINCIPAL_SKILLS_DOWN_SQL = `
DROP TABLE IF EXISTS agent_principal_skills;
`;

function textValue(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || raw.trim() === '' || /[\u0000\r\n]/u.test(raw)) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
  return raw.trim();
}

function skillName(raw: unknown): string {
  const value = textValue(raw, 'skillName');
  if (!/^[a-z0-9][a-z0-9._-]{0,127}$/u.test(value)) {
    throw new TypeError('skillName contains unsafe characters');
  }
  return value;
}

/** Lexical validation used before a path reaches a Podman mount plan. */
export function validatePrincipalSkillRoot(raw: unknown): string {
  const value = textValue(raw, 'skillRoot');
  if (!isAbsolute(value) || value.includes('\\') || value.split('/').includes('..')) {
    throw new TypeError('skillRoot must be an absolute POSIX path without traversal');
  }
  return resolve(value);
}

function boolValue(raw: unknown, fallback = false): boolean {
  return typeof raw === 'boolean' ? raw : raw === 't' ? true : raw === 'f' ? false : fallback;
}

function dateValue(raw: unknown): string {
  return raw instanceof Date ? raw.toISOString() : typeof raw === 'string' ? raw : new Date(0).toISOString();
}

function parseRow(row: Record<string, unknown>): AgentPrincipalSkillRow {
  return {
    larkAppId: textValue(row.lark_app_id, 'lark_app_id'),
    openId: textValue(row.open_id, 'open_id'),
    name: skillName(row.skill_name),
    rootDir: validatePrincipalSkillRoot(row.skill_root),
    enabled: boolValue(row.enabled, true),
    priority: Number.isSafeInteger(Number(row.priority)) ? Number(row.priority) : 100,
    createdAt: dateValue(row.created_at),
    updatedAt: dateValue(row.updated_at),
  };
}

function keyValues(key: AgentPrincipalKey): [string, string] {
  return [textValue(key.larkAppId, 'larkAppId'), textValue(key.openId, 'openId')];
}

function toLookupError(error: unknown): AgentPrincipalLookupError {
  if (error instanceof AgentPrincipalLookupError) return error;
  return new AgentPrincipalLookupError('database_unavailable', 'agent principal database unavailable');
}

async function inTransaction<T>(db: SqlExecutor, operation: (tx: SqlExecutor) => Promise<T>): Promise<T> {
  const connect = (db as Partial<SqlPool>).connect;
  if (typeof connect === 'function') {
    let client: SqlTransaction;
    try { client = await connect.call(db); } catch (error) { throw toLookupError(error); }
    try {
      await client.query('BEGIN');
      const result = await operation(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw toLookupError(error);
    } finally {
      client.release();
    }
  }
  await db.query('BEGIN');
  try {
    const result = await operation(db);
    await db.query('COMMIT');
    return result;
  } catch (error) {
    await db.query('ROLLBACK').catch(() => undefined);
    throw toLookupError(error);
  }
}

/** Read the principal's explicit skill snapshot in deterministic order. */
export async function readPrincipalSkillRows(
  db: SqlExecutor,
  key: AgentPrincipalKey,
): Promise<AgentPrincipalSkillRow[]> {
  try {
    const result = await db.query<Record<string, unknown>>(
      `SELECT lark_app_id, open_id, skill_name, skill_root, enabled, priority, created_at, updated_at
         FROM agent_principal_skills
        WHERE lark_app_id = $1 AND open_id = $2 AND enabled = true
        ORDER BY priority ASC, skill_name ASC`,
      keyValues(key),
    );
    return result.rows.map(parseRow);
  } catch (error) {
    throw toLookupError(error);
  }
}

/** Replace the explicit list atomically; an empty list is a deliberate clear. */
export async function replacePrincipalSkillRows(
  db: SqlExecutor,
  key: AgentPrincipalKey,
  rows: readonly Pick<AgentPrincipalSkillRow, 'name' | 'rootDir' | 'enabled' | 'priority'>[],
): Promise<AgentPrincipalSkillRow[]> {
  const [appId, openId] = keyValues(key);
  const normalized = rows.map(row => ({
    name: skillName(row.name),
    rootDir: validatePrincipalSkillRoot(row.rootDir),
    enabled: row.enabled !== false,
    priority: Number.isSafeInteger(row.priority) && row.priority >= 0 ? row.priority : 100,
  }));
  try {
    return await inTransaction(db, async tx => {
      await tx.query(
        `DELETE FROM agent_principal_skills WHERE lark_app_id = $1 AND open_id = $2`,
        [appId, openId],
      );
      const result: AgentPrincipalSkillRow[] = [];
      for (const row of normalized) {
        const inserted = await tx.query<Record<string, unknown>>(
          `INSERT INTO agent_principal_skills
             (lark_app_id, open_id, skill_name, skill_root, enabled, priority)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING lark_app_id, open_id, skill_name, skill_root, enabled, priority, created_at, updated_at`,
          [appId, openId, row.name, row.rootDir, row.enabled, row.priority],
        );
        if (inserted.rows[0]) result.push(parseRow(inserted.rows[0]));
      }
      return result;
    });
  } catch (error) {
    throw toLookupError(error);
  }
}

/** Add defaults without overwriting a principal's explicit policy. */
export async function ensureDefaultPrincipalSkillRows(
  db: SqlExecutor,
  key: AgentPrincipalKey,
  roots: readonly FrozenPrincipalSkillBinding[] = discoverDefaultPrincipalSkills(),
): Promise<void> {
  const [appId, openId] = keyValues(key);
  try {
    await inTransaction(db, async tx => {
      for (const [priority, row] of roots.entries()) {
        const normalized = normalizeSkillBinding(row);
        await tx.query(
          `INSERT INTO agent_principal_skills
             (lark_app_id, open_id, skill_name, skill_root, enabled, priority)
           VALUES ($1, $2, $3, $4, true, $5)
           ON CONFLICT (lark_app_id, open_id, skill_name) DO NOTHING`,
          [appId, openId, normalized.name, normalized.rootDir, priority],
        );
      }
    });
  } catch (error) {
    throw toLookupError(error);
  }
}

function normalizeSkillBinding(binding: FrozenPrincipalSkillBinding): FrozenPrincipalSkillBinding {
  const name = skillName(binding.name);
  const rootDir = validatePrincipalSkillRoot(binding.rootDir);
  const entrypoint = textValue(binding.entrypoint || 'SKILL.md', 'skillEntrypoint');
  if (entrypoint !== 'SKILL.md') throw new TypeError('skill entrypoint must be SKILL.md');
  return {
    name,
    rootDir,
    entrypoint,
    ...(binding.version ? { version: textValue(binding.version, 'skillVersion') } : {}),
    ...(binding.checksum ? { checksum: textValue(binding.checksum, 'skillChecksum') } : {}),
  };
}

/**
 * Resolve the three operator-approved defaults from the host without ever
 * falling back to the entire ~/.codex/skills tree. Missing defaults are simply
 * omitted; a caller can surface that diagnostic and refuse a guest launch.
 */
export function discoverDefaultPrincipalSkills(options: {
  readonly roots?: readonly string[];
} = {}): FrozenPrincipalSkillBinding[] {
  const roots = options.roots ?? [
    process.env.BOTMUX_PRINCIPAL_SKILLS_ROOT,
    '/mnt/c/Users/admin/.codex/skills',
    join(homedir(), '.codex', 'skills'),
    join(homedir(), '.botmux', 'skills', 'store'),
  ].filter((value): value is string => typeof value === 'string' && value.trim() !== '');
  const result: FrozenPrincipalSkillBinding[] = [];
  for (const name of DEFAULT_PRINCIPAL_SKILL_NAMES) {
    for (const root of roots) {
      const candidate = join(resolve(root), name);
      try {
        const stat = lstatSync(candidate);
        const entrypoint = join(candidate, 'SKILL.md');
        const entryStat = lstatSync(entrypoint);
        if (!stat.isDirectory() || stat.isSymbolicLink() || !entryStat.isFile() || entryStat.isSymbolicLink()) continue;
        const realRoot = realpathSync(candidate);
        result.push({ name, rootDir: realRoot, entrypoint: 'SKILL.md' });
        break;
      } catch {
        // Try the next known root. Do not expose a missing or malformed path.
      }
    }
  }
  return result;
}

/**
 * Convert DB rows into the frozen launch form and re-check the leaf shape.
 * This is deliberately stricter than SQL: a DB operator cannot make a
 * symlinked ~/.codex/skills parent or an arbitrary directory a guest mount.
 */
export function freezePrincipalSkillRows(rows: readonly AgentPrincipalSkillRow[]): FrozenPrincipalSkillBinding[] {
  return rows
    .filter(row => row.enabled)
    .sort((a, b) => a.priority - b.priority || a.name.localeCompare(b.name))
    .map(row => {
      const binding = normalizeSkillBinding({ name: row.name, rootDir: row.rootDir, entrypoint: 'SKILL.md' });
      if (basename(dirname(binding.rootDir)) !== 'skills' && basename(dirname(binding.rootDir)) !== 'store') {
        throw new AgentPrincipalLookupError('credential_incompatible', 'principal skill root is not an approved skills leaf');
      }
      let rootStat: ReturnType<typeof lstatSync>;
      try { rootStat = lstatSync(binding.rootDir); } catch {
        throw new AgentPrincipalLookupError('credential_incompatible', 'principal skill root is unavailable');
      }
      if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
        throw new AgentPrincipalLookupError('credential_incompatible', 'principal skill root is not a regular directory');
      }
      const entrypointPath = join(binding.rootDir, binding.entrypoint);
      let entryStat: ReturnType<typeof lstatSync> | undefined;
      try { entryStat = lstatSync(entrypointPath); } catch { /* handled below */ }
      if (!existsSync(entrypointPath) || !entryStat || entryStat.isSymbolicLink() || !entryStat.isFile()) {
        throw new AgentPrincipalLookupError('credential_incompatible', 'principal skill entrypoint is unavailable');
      }
      return binding;
    });
}
