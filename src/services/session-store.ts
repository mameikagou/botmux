import { readFileSync, writeFileSync, mkdirSync, existsSync, renameSync, readdirSync, unlinkSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { config } from '../config.js';
import { logger } from '../utils/logger.js';
import { withFileLockSync } from '../utils/file-lock.js';
import { cleanupMaterializedDashboardImages } from '../core/dashboard-images.js';
import { deleteFrozenCards } from './frozen-card-store.js';
import type { Session } from '../types.js';

let sessions: Map<string, Session> = new Map();
let loaded = false;
let currentAppId: string | undefined;
// Only the store-owning daemon process may create/import the SQLite store.
// Workers spawned from a NEWER dist by a still-running OLDER daemon must not
// bootstrap a .db while that daemon keeps writing JSON — the mixed upgrade
// window would fork the two representations.
let sqliteBootstrapAllowed = true;

// Legacy fields from the removed「处理中」placeholder-card PATCH delivery. They
// no longer exist on Session and nothing reads them, but sessions persisted
// before the removal still carry them on disk. Strip on write so the store
// converges to clean on the first save (daemon + CLI both call this).
const LEGACY_PENDING_CARD_FIELDS = ['pendingResponseCardId', 'pendingResponseCardState', 'lastPatchedResponseCardId'] as const;
export function stripLegacyPendingCardFields(session: Record<string, unknown>): void {
  for (const f of LEGACY_PENDING_CARD_FIELDS) delete session[f];
}

// ─── SQLite engine plumbing ──────────────────────────────────────────────────
// Per-bot session rows live in `sessions-<appId>.db` (legacy no-appId store:
// `sessions.db`), one table, whole-row JSON column. The TS `Session` type stays
// the schema authority; the generated columns below only serve hot lookups.
// The pre-SQLite JSON files are frozen in place on first import and never
// written again — reinstalling an older botmux and restarting reads them as of
// the freeze instant (the rollback story for the migration window).
//
// Mixed upgrade window (npm upgraded, daemon not yet restarted): every
// cross-process reader and CLI offline write path resolves each store as
// "use the .db when it exists, else the .json".

interface SqliteStatementLike {
  get(...params: unknown[]): unknown;
  all(...params: unknown[]): unknown[];
  run(...params: unknown[]): unknown;
}
interface SqliteDatabaseLike {
  exec(sql: string): void;
  prepare(sql: string): SqliteStatementLike;
  close(): void;
}
type SqliteModuleLike = {
  DatabaseSync: new (path: string, opts?: { readOnly?: boolean }) => SqliteDatabaseLike;
};

const SQLITE_BUSY_TIMEOUT_MS = 3000;
const SQLITE_NODE_VERSION_HINT = 'Node ≥ 22.13.0（23.x 需 ≥ 23.4.0）';

const SESSIONS_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  row TEXT NOT NULL,
  chat_id TEXT GENERATED ALWAYS AS (json_extract(row, '$.chatId')) VIRTUAL,
  root_message_id TEXT GENERATED ALWAYS AS (json_extract(row, '$.rootMessageId')) VIRTUAL,
  scope TEXT GENERATED ALWAYS AS (json_extract(row, '$.scope')) VIRTUAL
);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_root_message_id ON sessions(root_message_id, status);
CREATE INDEX IF NOT EXISTS idx_sessions_chat_scope ON sessions(chat_id, scope, status);
`;

let sqliteModule: SqliteModuleLike | null | undefined;
/** Simulate a Node runtime without node:sqlite (createRequire bypasses the
 *  vitest module graph, so a mock cannot intercept it). */
export function __testOnly_setSqliteUnavailable(unavailable: boolean): void {
  sqliteModule = unavailable ? null : undefined;
}
function loadSqliteModule(): SqliteModuleLike | null {
  if (sqliteModule !== undefined) return sqliteModule;
  // ESM 下没有裸 require，必须走 createRequire（同 adapters/cli/opencode.ts 的教训）。
  try {
    const req = createRequire(import.meta.url);
    sqliteModule = req('node:sqlite') as SqliteModuleLike;
  } catch {
    sqliteModule = null;
  }
  return sqliteModule;
}

/** node:sqlite is unavailable on this Node runtime but a SQLite store exists
 *  (or must be created). Distinct class so best-effort scan loops can rethrow
 *  it instead of degrading a capability failure into "file skipped". */
export class SessionStoreSqliteUnavailableError extends Error {
  override readonly name = 'SessionStoreSqliteUnavailableError';
}

function requireSqliteModule(context: string): SqliteModuleLike {
  const mod = loadSqliteModule();
  if (!mod) {
    throw new SessionStoreSqliteUnavailableError(
      `${context}需要 node:sqlite，但当前 Node ${process.version} 不提供。请升级 ${SQLITE_NODE_VERSION_HINT} 后重试。`,
    );
  }
  return mod;
}

/** Startup capability gate for the daemon. npm only WARNS on an engines
 *  mismatch, so this probe is the real gate: fail fast with an actionable
 *  message instead of failing later on the first store touch. */
export function assertSqliteSupported(): void {
  requireSqliteModule('botmux 会话存储（SQLite 引擎）');
}

/** Open the store the daemon/worker owns for read-write use (WAL + NORMAL +
 *  busy_timeout, schema ensured). Durability matches the previous JSON
 *  tmp+rename (no fsync) — deliberately not upgraded in this step. */
function openDbForOwnStore(path: string): SqliteDatabaseLike {
  const mod = requireSqliteModule(`会话存储 ${basename(path)} `);
  const db = new mod.DatabaseSync(path);
  db.exec(`PRAGMA busy_timeout = ${SQLITE_BUSY_TIMEOUT_MS};`);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA synchronous = NORMAL;');
  db.exec(SESSIONS_SCHEMA_SQL);
  return db;
}

/** Open somebody's store for reading. Read-write first so a stale WAL left by
 *  a crashed daemon can be recovered; fall back to read-only for sandboxed
 *  readers whose grant on the .db is read-only (a live daemon maintains the
 *  -shm they piggyback on). Callers must only SELECT. */
function openDbForRead(path: string): SqliteDatabaseLike {
  const mod = requireSqliteModule(`会话存储 ${basename(path)} `);
  let db: SqliteDatabaseLike;
  try {
    db = new mod.DatabaseSync(path);
  } catch {
    db = new mod.DatabaseSync(path, { readOnly: true });
  }
  db.exec(`PRAGMA busy_timeout = ${SQLITE_BUSY_TIMEOUT_MS};`);
  return db;
}

interface OwnSqliteStore {
  db: SqliteDatabaseLike;
  selectRow: SqliteStatementLike;
  selectAll: SqliteStatementLike;
  upsert: SqliteStatementLike;
}
let ownStore: OwnSqliteStore | undefined;

function attachOwnStore(path: string): OwnSqliteStore {
  const db = openDbForOwnStore(path);
  ownStore = {
    db,
    selectRow: db.prepare('SELECT row FROM sessions WHERE session_id = ?'),
    selectAll: db.prepare('SELECT session_id, row FROM sessions'),
    upsert: db.prepare(
      'INSERT INTO sessions (session_id, status, row) VALUES (?, ?, ?) '
      + 'ON CONFLICT(session_id) DO UPDATE SET status = excluded.status, row = excluded.row',
    ),
  };
  return ownStore;
}

function sessionStatusText(value: unknown): string {
  const status = (value as { status?: unknown } | null | undefined)?.status;
  return typeof status === 'string' ? status : '';
}

let testOnlyBeforeRowPersist: ((sessionId: string) => void) | undefined;
/** Failure injection for the SQLite row write (the JSON engine was injectable
 *  through a node:fs mock; node:sqlite bypasses node:fs). */
export function __testOnly_setBeforeRowPersist(hook: ((sessionId: string) => void) | undefined): void {
  testOnlyBeforeRowPersist = hook;
}

// ─── Store file resolution (db-else-json) ────────────────────────────────────

type StoreFileRef = {
  /** undefined = the legacy no-appId store. */
  appId?: string;
  kind: 'sqlite' | 'json';
  path: string;
};

function storeDbFileName(appId: string | undefined): string {
  return appId ? `sessions-${appId}.db` : 'sessions.db';
}
function storeJsonFileName(appId: string | undefined): string {
  return appId ? `sessions-${appId}.json` : 'sessions.json';
}

/** Per-store rule for every cross-process reader and CLI offline writer:
 *  use the .db when it exists, else the .json. */
function resolveStoreFile(appId: string | undefined, dataDir: string): StoreFileRef {
  const dbPath = join(dataDir, storeDbFileName(appId));
  if (existsSync(dbPath)) return { appId, kind: 'sqlite', path: dbPath };
  return { appId, kind: 'json', path: join(dataDir, storeJsonFileName(appId)) };
}

/** Group a directory listing into one ref per store identity, .db winning. */
function storeRefsFromNames(names: readonly string[], dataDir: string): StoreFileRef[] {
  const dbNames = new Map<string, string>();
  const jsonNames = new Map<string, string>();
  for (const name of names) {
    if (name === 'sessions.db') dbNames.set('', name);
    else if (name === 'sessions.json') jsonNames.set('', name);
    else if (name.startsWith('sessions-') && name.endsWith('.db')) {
      dbNames.set(name.slice('sessions-'.length, -'.db'.length), name);
    } else if (name.startsWith('sessions-') && name.endsWith('.json')) {
      jsonNames.set(name.slice('sessions-'.length, -'.json'.length), name);
    }
  }
  const refs: StoreFileRef[] = [];
  for (const key of new Set([...dbNames.keys(), ...jsonNames.keys()])) {
    const dbName = dbNames.get(key);
    refs.push({
      appId: key === '' ? undefined : key,
      kind: dbName ? 'sqlite' : 'json',
      path: join(dataDir, dbName ?? jsonNames.get(key)!),
    });
  }
  return refs;
}

/** All [key, value] entries of one store file. Throws on an unreadable store;
 *  callers decide skip-vs-propagate (capability errors always propagate). */
function readStoreEntries(ref: StoreFileRef): [string, Session][] {
  if (ref.kind === 'json') {
    const parsed = JSON.parse(readFileSync(ref.path, 'utf-8')) as unknown;
    if (!parsed || typeof parsed !== 'object') return [];
    return Object.entries(parsed as Record<string, Session>);
  }
  const db = openDbForRead(ref.path);
  try {
    const rows = db.prepare('SELECT session_id, row FROM sessions').all() as { session_id: string; row: string }[];
    const entries: [string, Session][] = [];
    for (const r of rows) {
      try { entries.push([r.session_id, JSON.parse(r.row) as Session]); } catch { /* skip unparseable row */ }
    }
    return entries;
  } finally {
    db.close();
  }
}

/** Point-read one key from one store file. Throws on an unreadable store. */
function readStoreRowByKey(ref: StoreFileRef, sessionId: string): Session | undefined {
  if (ref.kind === 'json') {
    const parsed = JSON.parse(readFileSync(ref.path, 'utf-8')) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
    return (parsed as Record<string, Session>)[sessionId];
  }
  // The daemon's hot freshness reads hit its own store — reuse the attached
  // connection instead of opening one per call.
  if (ownStore && loaded && ref.appId === currentAppId && ref.path === getDbPath()) {
    const hit = ownStore.selectRow.get(sessionId) as { row: string } | undefined;
    return hit ? JSON.parse(hit.row) as Session : undefined;
  }
  const db = openDbForRead(ref.path);
  try {
    const hit = db.prepare('SELECT row FROM sessions WHERE session_id = ?').get(sessionId) as { row: string } | undefined;
    return hit ? JSON.parse(hit.row) as Session : undefined;
  } finally {
    db.close();
  }
}

/** The active rows of one store file, optionally narrowed by an indexed hint. */
function readStoreActiveRows(
  ref: StoreFileRef,
  hint?: { rootMessageId?: string; chatScopeChatId?: string },
): Session[] {
  if (ref.kind === 'json') {
    const parsed = JSON.parse(readFileSync(ref.path, 'utf-8')) as unknown;
    if (!parsed || typeof parsed !== 'object') return [];
    return Object.values(parsed as Record<string, Session>).filter(s => s?.status === 'active');
  }
  const db = openDbForRead(ref.path);
  try {
    let sql = "SELECT row FROM sessions WHERE status = 'active'";
    const params: unknown[] = [];
    if (hint?.rootMessageId !== undefined) {
      sql += ' AND root_message_id = ?';
      params.push(hint.rootMessageId);
    }
    if (hint?.chatScopeChatId !== undefined) {
      sql += " AND chat_id = ? AND scope = 'chat'";
      params.push(hint.chatScopeChatId);
    }
    const rows = db.prepare(sql).all(...params) as { row: string }[];
    const out: Session[] = [];
    for (const r of rows) {
      try { out.push(JSON.parse(r.row) as Session); } catch { /* skip unparseable row */ }
    }
    return out;
  } finally {
    db.close();
  }
}

/** The active row no longer has the lineage/ownership sampled by the caller. */
export class RiffLineageOwnershipError extends Error {
  override readonly name = 'RiffLineageOwnershipError';
}

export type RiffDurableOwner = {
  pid: number | null;
  larkAppId: string | null;
  backendType: string | null;
};

export type ActiveRiffShutdownSnapshot = {
  sessionId: string;
  taskId: string | null;
  owner: RiffDurableOwner;
};

export type ActiveRiffLineageBatchUpdate = ActiveRiffShutdownSnapshot & {
  targetTaskId: string | null;
  expectedCurrentTaskIds: readonly (string | null)[];
};

export type RiffLineageBatchFailureStage =
  | 'prewrite_ownership'
  | 'prewrite_io'
  | 'postrename_ambiguity';

export class RiffLineageBatchError extends Error {
  override readonly name = 'RiffLineageBatchError';

  constructor(
    readonly stage: RiffLineageBatchFailureStage,
    readonly sessionIds: readonly string[],
    message: string,
  ) {
    super(message);
  }
}

function riffDurableOwner(session: Session): RiffDurableOwner {
  return {
    pid: session.pid ?? null,
    larkAppId: session.larkAppId ?? null,
    backendType: session.backendType ?? null,
  };
}

function riffOwnersEqual(left: RiffDurableOwner, right: RiffDurableOwner): boolean {
  return left.pid === right.pid
    && left.larkAppId === right.larkAppId
    && left.backendType === right.backendType;
}

let testOnlyAfterRiffBatchRename: (() => void) | undefined;
export function __testOnly_setAfterRiffBatchRename(hook: (() => void) | undefined): void {
  testOnlyAfterRiffBatchRename = hook;
}

/**
 * Initialise session store for a specific bot (multi-daemon mode).
 * When appId is set, sessions are stored in `sessions-{appId}.db`.
 * When unset, uses the legacy no-appId store (`sessions.db`).
 *
 * `owner: false` marks a non-owning process (worker): it reads whichever
 * engine exists (db-else-json) but never bootstraps/imports the SQLite store —
 * an old daemon can spawn workers from a newer dist during the upgrade window,
 * and only the daemon itself may flip the on-disk engine.
 */
export function init(appId?: string, opts: { owner?: boolean } = {}): void {
  currentAppId = appId;
  sqliteBootstrapAllowed = opts.owner !== false;
  loaded = false;
  sessions = new Map();
  if (ownStore) {
    try { ownStore.db.close(); } catch { /* already closed */ }
    ownStore = undefined;
  }
}

function getFilePath(): string {
  return join(config.session.dataDir, storeJsonFileName(currentAppId));
}

function getDbPath(): string {
  return join(config.session.dataDir, storeDbFileName(currentAppId));
}

function ensureDir(): void {
  const dir = dirname(getFilePath());
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
}

// A short-lived /repo bug recreated chat-scope sessions with the chat routing
// anchor (`oc_...`) copied into rootMessageId and omitted scope. That shape is
// impossible for a real thread: Lark message ids are `om_...`. Repair only this
// narrow signature so ordinary legacy records without scope keep their
// documented thread fallback. The original trace message cannot be recovered,
// but chat routing does not use rootMessageId.
export function repairMissingChatScope(session: unknown): boolean {
  if (!session || typeof session !== 'object' || Array.isArray(session)) return false;
  const record = session as Record<string, unknown>;
  if (
    record.scope === undefined
    && typeof record.chatId === 'string'
    && record.chatId.startsWith('oc_')
    && typeof record.rootMessageId === 'string'
    && record.rootMessageId === record.chatId
  ) {
    record.scope = 'chat';
    return true;
  }
  return false;
}

function repairMissingChatScopes(): Session[] {
  const repaired: Session[] = [];
  for (const session of sessions.values()) {
    if (repairMissingChatScope(session)) repaired.push(session);
  }
  return repaired;
}

/** The JSON rows today's load()/migration would have produced for this store:
 *  the per-bot file's entries when it exists, else the legacy `sessions.json`
 *  rows belonging to this bot; scope repair applied, legacy card fields
 *  stripped, closed rows included. Parse failures degrade to an empty store —
 *  exactly like the previous loader. */
function readJsonEntriesForImport(jsonFp: string): [string, Session][] {
  let entries: [string, Session][] = [];
  if (existsSync(jsonFp)) {
    try {
      const data = JSON.parse(readFileSync(jsonFp, 'utf-8')) as Record<string, Session>;
      entries = Object.entries(data);
    } catch (err) {
      logger.error(`Failed to load sessions: ${err}`);
      return [];
    }
  } else if (currentAppId) {
    const legacyFp = join(config.session.dataDir, 'sessions.json');
    if (!existsSync(legacyFp)) return [];
    try {
      const data = JSON.parse(readFileSync(legacyFp, 'utf-8')) as Record<string, Session>;
      entries = Object.entries(data).filter(([, v]) => v?.larkAppId === currentAppId);
    } catch (err) {
      logger.error(`Failed to migrate sessions from legacy file: ${err}`);
      return [];
    }
  } else {
    return [];
  }
  for (const [, value] of entries) {
    if (value && typeof value === 'object') {
      repairMissingChatScope(value);
      stripLegacyPendingCardFields(value as unknown as Record<string, unknown>);
    }
  }
  return entries;
}

/** One-shot deterministic import: build the store at `<db>.tmp`, commit, then
 *  rename into place so readers only ever see a complete database. The caller
 *  holds the same JSON file lock daemon saves and offline CLI mutations use,
 *  so the imported snapshot cannot race a concurrent JSON writer. The source
 *  JSON is left frozen in place (the rollback path for the upgrade window). */
function importJsonStoreToSqlite(dbFp: string, jsonFp: string): number {
  const mod = requireSqliteModule(`会话存储 ${basename(dbFp)} 首次导入`);
  const tmpFp = `${dbFp}.tmp`;
  for (const suffix of ['', '-wal', '-shm']) {
    try { unlinkSync(`${tmpFp}${suffix}`); } catch { /* no leftover from a crashed import */ }
  }
  const entries = readJsonEntriesForImport(jsonFp);
  const tmp = new mod.DatabaseSync(tmpFp);
  try {
    tmp.exec(`PRAGMA busy_timeout = ${SQLITE_BUSY_TIMEOUT_MS};`);
    tmp.exec('PRAGMA journal_mode = WAL;');
    tmp.exec('PRAGMA synchronous = NORMAL;');
    tmp.exec(SESSIONS_SCHEMA_SQL);
    tmp.exec('BEGIN');
    const insert = tmp.prepare('INSERT OR REPLACE INTO sessions (session_id, status, row) VALUES (?, ?, ?)');
    for (const [key, value] of entries) {
      insert.run(key, sessionStatusText(value), JSON.stringify(value));
    }
    tmp.exec('COMMIT');
    tmp.close();
    renameSync(tmpFp, dbFp);
    return entries.length;
  } catch (err) {
    try { tmp.close(); } catch { /* already closed */ }
    for (const suffix of ['', '-wal', '-shm']) {
      try { unlinkSync(`${tmpFp}${suffix}`); } catch { /* best-effort orphan cleanup */ }
    }
    throw err;
  }
}

// Sessions persisted before 2026-04-29 lack `cliId`; consumers must fall back to 'unknown' at the render boundary.
function load(): void {
  if (loaded) return;
  ensureDir();
  const dbFp = getDbPath();
  const jsonFp = getFilePath();

  if (!existsSync(dbFp) && sqliteBootstrapAllowed) {
    // First start on the SQLite engine: import this store's JSON rows (or
    // create an empty store) under the same lock every JSON writer uses.
    withFileLockSync(jsonFp, () => {
      if (existsSync(dbFp)) return; // another owning process won the import
      const imported = importJsonStoreToSqlite(dbFp, jsonFp);
      if (imported > 0) {
        logger.info(`Imported ${imported} session row(s) from JSON into ${dbFp}; JSON files stay frozen for rollback`);
      }
    });
  }

  if (existsSync(dbFp)) {
    const store = attachOwnStore(dbFp);
    sessions = new Map();
    for (const [key, value] of readOwnStoreAllRows(store)) sessions.set(key, value);
    const repaired = repairMissingChatScopes();
    if (repaired.length > 0) {
      try {
        for (const session of repaired) {
          store.upsert.run(session.sessionId, sessionStatusText(session), JSON.stringify(session));
        }
        logger.info(`Repaired ${repaired.length} scope-less chat session(s) in ${dbFp}`);
      } catch (err) {
        // Loading succeeded, so keep the in-memory sessions available even
        // if the best-effort repair cannot be persisted yet.
        logger.error(`Failed to persist repaired chat session scopes: ${err}`);
      }
    }
    logger.info(`Loaded ${sessions.size} sessions from ${dbFp}`);
    loaded = true;
    return;
  }

  // JSON engine (non-owning process before the daemon has imported, or a
  // pre-SQLite store this process may not bootstrap). Behaviour unchanged.
  withFileLockSync(jsonFp, () => {
    if (existsSync(jsonFp)) {
      try {
        const data = JSON.parse(readFileSync(jsonFp, 'utf-8'));
        sessions = new Map(Object.entries(data));
        const repaired = repairMissingChatScopes();
        if (repaired.length > 0) {
          try {
            const tmpFp = `${jsonFp}.${process.pid}.${randomUUID()}.tmp`;
            writeFileSync(tmpFp, JSON.stringify(Object.fromEntries(sessions), null, 2), 'utf-8');
            renameSync(tmpFp, jsonFp);
            logger.info(`Repaired ${repaired.length} scope-less chat session(s) in ${jsonFp}`);
          } catch (err) {
            // Loading succeeded, so keep the in-memory sessions available even
            // if the best-effort repair cannot be persisted yet.
            logger.error(`Failed to persist repaired chat session scopes: ${err}`);
          }
        }
        logger.info(`Loaded ${sessions.size} sessions from ${jsonFp}`);
      } catch (err) {
        logger.error(`Failed to load sessions: ${err}`);
        sessions = new Map();
      }
    } else if (currentAppId) {
      // Per-bot file doesn't exist — migrate matching legacy rows while still
      // holding the same lock used by daemon saves and offline CLI mutations.
      const legacyFp = join(config.session.dataDir, 'sessions.json');
      if (existsSync(legacyFp)) {
        try {
          const data: Record<string, Session> = JSON.parse(readFileSync(legacyFp, 'utf-8'));
          sessions = new Map();
          for (const [k, v] of Object.entries(data)) {
            if (v.larkAppId === currentAppId) sessions.set(k, v);
          }
          if (sessions.size > 0) {
            const repaired = repairMissingChatScopes();
            const obj = Object.fromEntries(sessions);
            const tmpFp = `${jsonFp}.${process.pid}.${randomUUID()}.tmp`;
            writeFileSync(tmpFp, JSON.stringify(obj, null, 2), 'utf-8');
            renameSync(tmpFp, jsonFp);
            logger.info(`Migrated ${sessions.size} sessions from sessions.json to ${jsonFp}`);
            if (repaired.length > 0) {
              logger.info(`Repaired ${repaired.length} scope-less chat session(s) during migration`);
            }
          }
        } catch (err) {
          logger.error(`Failed to migrate sessions from legacy file: ${err}`);
          sessions = new Map();
        }
      }
    }
  });
  loaded = true;
}

function readOwnStoreAllRows(store: OwnSqliteStore): [string, Session][] {
  const rows = store.selectAll.all() as { session_id: string; row: string }[];
  const entries: [string, Session][] = [];
  for (const r of rows) {
    try { entries.push([r.session_id, JSON.parse(r.row) as Session]); } catch { /* skip unparseable row */ }
  }
  return entries;
}

function readExistingSessionsFromDisk(fp: string): { raw: string; parsed: Record<string, Session> } {
  if (!existsSync(fp)) return { raw: '', parsed: {} };
  try {
    const raw = readFileSync(fp, 'utf-8');
    return { raw, parsed: JSON.parse(raw) as Record<string, Session> };
  } catch {
    return { raw: '', parsed: {} };
  }
}

function readSessionsProjectionStrict(fp: string): { raw: string; parsed: Record<string, Session> } {
  if (!existsSync(fp)) return { raw: '', parsed: {} };
  const raw = readFileSync(fp, 'utf-8');
  const value = JSON.parse(raw) as unknown;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`invalid sessions projection at ${fp}`);
  }
  return { raw, parsed: value as Record<string, Session> };
}

function duplicateIds(ids: readonly string[]): string[] {
  const seen = new Set<string>();
  const duplicates = new Set<string>();
  for (const id of ids) {
    if (seen.has(id)) duplicates.add(id);
    else seen.add(id);
  }
  return [...duplicates];
}

/** Read-write connection to this process's own store for Riff/offline-style
 *  fresh access: the attached connection when loaded, else a short-lived one.
 *  Returns undefined when the store is still on the JSON engine. */
function withOwnStoreDbIfSqlite<T>(fn: (db: SqliteDatabaseLike) => T): T | undefined {
  if (ownStore) return fn(ownStore.db);
  const dbFp = getDbPath();
  if (!existsSync(dbFp)) return undefined;
  const db = openDbForOwnStore(dbFp);
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

/**
 * Sample every active Riff participant from one fresh sessions projection.
 * Fleet shutdown takes this snapshot before fencing any worker.
 */
export function getActiveRiffShutdownSnapshotsBatch(
  sessionIds: readonly string[],
  options: { maxWaitMs?: number } = {},
): ActiveRiffShutdownSnapshot[] {
  if (sessionIds.length === 0) return [];
  const duplicates = duplicateIds(sessionIds);
  if (duplicates.length > 0) {
    throw new RiffLineageBatchError(
      'prewrite_ownership',
      duplicates,
      `duplicate Riff shutdown session ids: ${duplicates.join(', ')}`,
    );
  }

  ensureDir();
  try {
    const sqliteResult = withOwnStoreDbIfSqlite((db): ActiveRiffShutdownSnapshot[] => {
      db.exec('BEGIN');
      try {
        const select = db.prepare('SELECT row FROM sessions WHERE session_id = ?');
        const fresh = new Map<string, Session | undefined>();
        for (const sessionId of sessionIds) {
          const hit = select.get(sessionId) as { row: string } | undefined;
          fresh.set(sessionId, hit ? JSON.parse(hit.row) as Session : undefined);
        }
        const invalid = sessionIds.filter((sessionId) => {
          const session = fresh.get(sessionId);
          return !session || session.status !== 'active';
        });
        if (invalid.length > 0) {
          throw new RiffLineageBatchError(
            'prewrite_ownership',
            invalid,
            `cannot snapshot non-active Riff sessions: ${invalid.join(', ')}`,
          );
        }
        return sessionIds.map((sessionId) => {
          const session = fresh.get(sessionId)!;
          return {
            sessionId,
            taskId: session.riffParentTaskId ?? null,
            owner: riffDurableOwner(session),
          };
        });
      } finally {
        // 读事务收尾：COMMIT 失败（事务已 abort）时必须 ROLLBACK，
        // 长驻连接绝不能滞留在事务里。
        try { db.exec('COMMIT'); } catch { try { db.exec('ROLLBACK'); } catch { /* txn already gone */ } }
      }
    });
    if (sqliteResult !== undefined) return sqliteResult;

    const fp = getFilePath();
    return withFileLockSync(fp, () => {
      const { parsed } = readSessionsProjectionStrict(fp);
      const invalid = sessionIds.filter((sessionId) => {
        const session = parsed[sessionId];
        return !session || session.status !== 'active';
      });
      if (invalid.length > 0) {
        throw new RiffLineageBatchError(
          'prewrite_ownership',
          invalid,
          `cannot snapshot non-active Riff sessions: ${invalid.join(', ')}`,
        );
      }
      return sessionIds.map((sessionId) => {
        const session = parsed[sessionId]!;
        return {
          sessionId,
          taskId: session.riffParentTaskId ?? null,
          owner: riffDurableOwner(session),
        };
      });
    }, { maxWaitMs: options.maxWaitMs });
  } catch (error) {
    if (error instanceof RiffLineageBatchError) throw error;
    throw new RiffLineageBatchError(
      'prewrite_io',
      [...sessionIds],
      `failed to snapshot active Riff sessions: ${String(error)}`,
    );
  }
}

/**
 * Commit every prepared Riff lineage as one compare-and-set transaction.
 * The published rows are read back before workers are allowed to exit.
 */
export function persistActiveRiffLineagesExactBatch(
  updates: readonly ActiveRiffLineageBatchUpdate[],
  options: { maxWaitMs?: number } = {},
): ActiveRiffShutdownSnapshot[] {
  if (updates.length === 0) return [];
  const sessionIds = updates.map(update => update.sessionId);
  const duplicates = duplicateIds(sessionIds);
  if (duplicates.length > 0) {
    throw new RiffLineageBatchError(
      'prewrite_ownership',
      duplicates,
      `duplicate Riff lineage batch session ids: ${duplicates.join(', ')}`,
    );
  }

  ensureDir();
  let published = false;
  try {
    const sqliteResult = withOwnStoreDbIfSqlite((db): ActiveRiffShutdownSnapshot[] => {
      const select = db.prepare('SELECT row FROM sessions WHERE session_id = ?');
      const update = db.prepare("UPDATE sessions SET status = ?, row = ? WHERE session_id = ?");
      let inTxn = false;
      let changed = false;
      try {
        db.exec('BEGIN IMMEDIATE');
        inTxn = true;
        const freshRows = new Map<string, { session: Session; raw: string } | undefined>();
        for (const sessionId of sessionIds) {
          const hit = select.get(sessionId) as { row: string } | undefined;
          freshRows.set(sessionId, hit ? { session: JSON.parse(hit.row) as Session, raw: hit.row } : undefined);
        }
        const conflicts: string[] = [];
        for (const u of updates) {
          const durable = freshRows.get(u.sessionId)?.session;
          const durableTaskId = durable?.riffParentTaskId ?? null;
          if (!durable
              || durable.status !== 'active'
              || !u.expectedCurrentTaskIds.some(candidate => candidate === durableTaskId)
              || !riffOwnersEqual(riffDurableOwner(durable), u.owner)) {
            conflicts.push(u.sessionId);
          }
        }
        if (conflicts.length > 0) {
          throw new RiffLineageBatchError(
            'prewrite_ownership',
            conflicts,
            `Riff lineage batch compare-and-set failed for: ${conflicts.join(', ')}`,
          );
        }
        for (const u of updates) {
          const fresh = freshRows.get(u.sessionId)!;
          const next: Session = {
            ...fresh.session,
            riffParentTaskId: u.targetTaskId ?? undefined,
          };
          stripLegacyPendingCardFields(next as unknown as Record<string, unknown>);
          const json = JSON.stringify(next);
          if (json !== fresh.raw) {
            update.run(sessionStatusText(next), json, u.sessionId);
            changed = true;
          }
        }
        db.exec('COMMIT');
        inTxn = false;
      } catch (err) {
        if (inTxn) { try { db.exec('ROLLBACK'); } catch { /* txn already gone */ } }
        throw err;
      }
      if (changed) {
        published = true;
        testOnlyAfterRiffBatchRename?.();
      }

      // Read back the committed rows before any worker may exit.
      const verifiedRows = new Map<string, Session | undefined>();
      for (const sessionId of sessionIds) {
        const hit = select.get(sessionId) as { row: string } | undefined;
        verifiedRows.set(sessionId, hit ? JSON.parse(hit.row) as Session : undefined);
      }
      const ambiguous = updates.filter((u) => {
        const durable = verifiedRows.get(u.sessionId);
        return !durable
          || durable.status !== 'active'
          || (durable.riffParentTaskId ?? null) !== u.targetTaskId
          || !riffOwnersEqual(riffDurableOwner(durable), u.owner);
      }).map(u => u.sessionId);
      if (ambiguous.length > 0) {
        throw new RiffLineageBatchError(
          published ? 'postrename_ambiguity' : 'prewrite_ownership',
          ambiguous,
          `Riff lineage batch readback mismatch for: ${ambiguous.join(', ')}`,
        );
      }

      const verified = updates.map((u) => ({
        sessionId: u.sessionId,
        taskId: u.targetTaskId,
        owner: riffDurableOwner(verifiedRows.get(u.sessionId)!),
      }));
      if (loaded) {
        for (const u of updates) {
          const cached = sessions.get(u.sessionId);
          if (cached) cached.riffParentTaskId = u.targetTaskId ?? undefined;
        }
      }
      return verified;
    });
    if (sqliteResult !== undefined) return sqliteResult;

    const fp = getFilePath();
    let tmpFp: string | undefined;
    try {
      return withFileLockSync(fp, () => {
        const { raw, parsed } = readSessionsProjectionStrict(fp);
        const conflicts: string[] = [];
        for (const update of updates) {
          const durable = parsed[update.sessionId];
          const durableTaskId = durable?.riffParentTaskId ?? null;
          if (!durable
              || durable.status !== 'active'
              || !update.expectedCurrentTaskIds.some(candidate => candidate === durableTaskId)
              || !riffOwnersEqual(riffDurableOwner(durable), update.owner)) {
            conflicts.push(update.sessionId);
          }
        }
        if (conflicts.length > 0) {
          throw new RiffLineageBatchError(
            'prewrite_ownership',
            conflicts,
            `Riff lineage batch compare-and-set failed for: ${conflicts.join(', ')}`,
          );
        }

        for (const update of updates) {
          const durable = parsed[update.sessionId]!;
          const next: Session = {
            ...durable,
            riffParentTaskId: update.targetTaskId ?? undefined,
          };
          stripLegacyPendingCardFields(next as unknown as Record<string, unknown>);
          parsed[update.sessionId] = next;
        }

        const json = JSON.stringify(parsed, null, 2);
        if (json !== raw) {
          tmpFp = `${fp}.${process.pid}.${randomUUID()}.tmp`;
          writeFileSync(tmpFp, json, 'utf-8');
          renameSync(tmpFp, fp);
          tmpFp = undefined;
          published = true;
          testOnlyAfterRiffBatchRename?.();
        }

        let verifiedProjection: Record<string, Session>;
        try {
          verifiedProjection = readSessionsProjectionStrict(fp).parsed;
        } catch (error) {
          throw new RiffLineageBatchError(
            published ? 'postrename_ambiguity' : 'prewrite_io',
            [...sessionIds],
            `failed to read back Riff lineage batch: ${String(error)}`,
          );
        }

        const ambiguous = updates.filter((update) => {
          const durable = verifiedProjection[update.sessionId];
          return !durable
            || durable.status !== 'active'
            || (durable.riffParentTaskId ?? null) !== update.targetTaskId
            || !riffOwnersEqual(riffDurableOwner(durable), update.owner);
        }).map(update => update.sessionId);
        if (ambiguous.length > 0) {
          throw new RiffLineageBatchError(
            published ? 'postrename_ambiguity' : 'prewrite_ownership',
            ambiguous,
            `Riff lineage batch readback mismatch for: ${ambiguous.join(', ')}`,
          );
        }

        const verified = updates.map((update) => ({
          sessionId: update.sessionId,
          taskId: update.targetTaskId,
          owner: riffDurableOwner(verifiedProjection[update.sessionId]!),
        }));
        if (loaded) {
          for (const update of updates) {
            const cached = sessions.get(update.sessionId);
            if (cached) cached.riffParentTaskId = update.targetTaskId ?? undefined;
          }
        }
        return verified;
      }, { maxWaitMs: options.maxWaitMs });
    } finally {
      if (tmpFp) {
        try { unlinkSync(tmpFp); } catch { /* best-effort orphan cleanup */ }
      }
    }
  } catch (error) {
    if (error instanceof RiffLineageBatchError) throw error;
    throw new RiffLineageBatchError(
      published ? 'postrename_ambiguity' : 'prewrite_io',
      [...sessionIds],
      `failed to persist Riff lineage batch: ${String(error)}`,
    );
  }
}

/** Whole-map JSON save — only for a store still on the JSON engine. */
function save(): void {
  ensureDir();
  const fp = getFilePath();
  withFileLockSync(fp, () => {
    const { raw: existingRaw } = readExistingSessionsFromDisk(fp);
    const obj: Record<string, Session> = {};
    for (const [k, v] of sessions) {
      stripLegacyPendingCardFields(v as unknown as Record<string, unknown>);
      obj[k] = v;
    }
    const json = JSON.stringify(obj, null, 2);
    // The daemon fires several updateSession()/save() calls per inbound message
    // (activity bump, pid, stream-card state, …) and many leave the serialized
    // file byte-identical. Skipping the temp-file write + rename in that case
    // elides the bulk of the redundant disk I/O.
    if (json === existingRaw) return;
    const tmpFp = `${fp}.${process.pid}.${randomUUID()}.tmp`;
    writeFileSync(tmpFp, json, 'utf-8');
    renameSync(tmpFp, fp);
  });
}

/** Persist ONE changed row. SQLite engine: dirty-row upsert (a redundant
 *  update that leaves the serialized row identical skips the write, the
 *  row-level analogue of the old byte-identical whole-file skip). JSON
 *  engine: the legacy whole-map save. */
function persistRow(session: Session): void {
  if (!ownStore) {
    save();
    return;
  }
  stripLegacyPendingCardFields(session as unknown as Record<string, unknown>);
  testOnlyBeforeRowPersist?.(session.sessionId);
  const json = JSON.stringify(session);
  const existing = ownStore.selectRow.get(session.sessionId) as { row: string } | undefined;
  if (existing?.row === json) return;
  ownStore.upsert.run(session.sessionId, sessionStatusText(session), json);
}

export function createSession(
  chatId: string,
  rootMessageId: string,
  title: string,
  chatType?: 'group' | 'p2p',
  scope?: 'thread' | 'chat',
): Session {
  load();
  const session: Session = {
    sessionId: randomUUID(),
    chatId,
    chatType,
    rootMessageId,
    scope,
    title,
    status: 'active',
    createdAt: new Date().toISOString(),
  };
  sessions.set(session.sessionId, session);
  persistRow(session);
  logger.info(`Created session ${session.sessionId} (thread: ${rootMessageId})`);
  return session;
}

export function getSession(sessionId: string): Session | undefined {
  load();
  return sessions.get(sessionId) ?? findInOtherFiles(sessionId);
}

const bridgeMarkerCleanupFences = new Map<string, Promise<void>>();

export function registerSessionBridgeSendMarkerCleanupFence(
  sessionId: string,
  fence: Promise<void>,
): void {
  bridgeMarkerCleanupFences.set(sessionId, fence);
  void fence.then(
    () => {
      if (bridgeMarkerCleanupFences.get(sessionId) === fence) {
        bridgeMarkerCleanupFences.delete(sessionId);
      }
    },
    () => {
      if (bridgeMarkerCleanupFences.get(sessionId) === fence) {
        bridgeMarkerCleanupFences.delete(sessionId);
      }
    },
  );
}

/**
 * Return a row only when it belongs to this process's currently-initialised
 * bot store. Mutating daemon endpoints must use this instead of getSession(),
 * whose cross-file fallback is intentionally read-only discovery.
 */
export function getOwnedSession(sessionId: string): Session | undefined {
  load();
  return sessions.get(sessionId);
}

/** Cross-process fresh read. SQLite engine: a point SELECT observes the last
 *  committed write (WAL orders daemon/CLI writers). JSON engine: ordered
 *  after writers by the shared file lock, as before. */
export function getSessionFresh(sessionId: string): Session | undefined {
  ensureDir();
  const dbFp = getDbPath();
  if (existsSync(dbFp)) {
    try {
      return readStoreRowByKey({ appId: currentAppId, kind: 'sqlite', path: dbFp }, sessionId);
    } catch (err) {
      if (err instanceof SessionStoreSqliteUnavailableError) throw err;
      return undefined;
    }
  }
  const fp = getFilePath();
  return withFileLockSync(fp, () => {
    if (!existsSync(fp)) return undefined;
    try {
      const data = JSON.parse(readFileSync(fp, 'utf-8')) as Record<string, Session>;
      return data[sessionId];
    } catch {
      return undefined;
    }
  });
}

/**
 * Search all session stores for a session not found in the current store.
 *
 * Sessions are partitioned per-bot, but agent-facing CLI subcommands
 * (`botmux send`, etc.) may be invoked in contexts where LARK_APP_ID isn't
 * set, so they can't pick the right store directly. Scanning all stores is
 * safe — these callers only read sessions.
 */
function findInOtherFiles(sessionId: string): Session | undefined {
  const dataDir = config.session.dataDir;
  let names: string[];
  try {
    names = readdirSync(dataDir);
  } catch { return undefined; }
  for (const ref of storeRefsFromNames(names, dataDir)) {
    if (ref.appId === currentAppId) continue;
    try {
      const hit = readStoreRowByKey(ref, sessionId);
      if (hit) return hit;
    } catch (err) {
      if (err instanceof SessionStoreSqliteUnavailableError) throw err;
      continue;
    }
  }
  return undefined;
}

export function cleanupSessionBridgeSendMarkersNow(sessionId: string): void {
  try { unlinkSync(join(config.session.dataDir, 'turn-sends', `${sessionId}.jsonl`)); } catch { /* absent/best effort */ }
}

export function cleanupSessionBridgeSendMarkers(sessionId: string): void {
  const fence = bridgeMarkerCleanupFences.get(sessionId);
  if (fence) {
    void fence.then(
      () => cleanupSessionBridgeSendMarkersNow(sessionId),
      () => cleanupSessionBridgeSendMarkersNow(sessionId),
    );
    return;
  }
  cleanupSessionBridgeSendMarkersNow(sessionId);
}

export function closeSession(
  sessionId: string,
  opts: { cleanupBridgeMarkers?: boolean; clearRiffParentTaskId?: boolean } = {},
): void {
  load();
  const session = sessions.get(sessionId);
  if (session) {
    const priorStatus = session.status;
    const priorClosedAt = session.closedAt;
    const priorRiffParentTaskId = session.riffParentTaskId;
    const priorDashboardAttachments = session.dashboardAttachments;
    const priorQueuedAttachments = session.queuedAttachments;
    session.status = 'closed';
    session.closedAt = new Date().toISOString();
    session.dashboardAttachments = undefined;
    session.queuedAttachments = undefined;
    // Riff cancellation has already completed before this durable transition.
    // Clear its retry handle in the same atomic save as status='closed'.
    if (opts.clearRiffParentTaskId) session.riffParentTaskId = undefined;
    try {
      persistRow(session);
    } catch (err) {
      session.status = priorStatus;
      session.closedAt = priorClosedAt;
      session.riffParentTaskId = priorRiffParentTaskId;
      session.dashboardAttachments = priorDashboardAttachments;
      session.queuedAttachments = priorQueuedAttachments;
      throw err;
    }
    if (session.larkAppId && priorDashboardAttachments?.length) {
      try {
        cleanupMaterializedDashboardImages(session.larkAppId, priorDashboardAttachments);
      } catch (error: any) {
        logger.warn(`Failed to clean Dashboard images for session ${sessionId}: ${error?.message ?? error}`);
      }
    }
    // turn-sends was originally a transient bridge-dedup file cleaned by a
    // live worker's close handler. Message previews now make its bounded tail
    // user-visible, so workerless/forced closes must apply the same cleanup;
    // otherwise closed sessions retain private reply text indefinitely.
    if (opts.cleanupBridgeMarkers !== false) cleanupSessionBridgeSendMarkers(sessionId);
    deleteFrozenCards(sessionId);
    logger.info(`Closed session ${sessionId}`);
  }
}

/**
 * Reactivate one explicitly closed row and discard every queued/setup owner in
 * the same durable write.  The close path has cleared these fields since
 * 2026-07, but older closed rows can still contain prepared input.  A generic
 * resume is an explicit new lifecycle and must never revive that abandoned
 * FIFO.
 */
export function reactivateClosedSession(
  sessionId: string,
): { ok: true; session: Session }
| { ok: false; error: 'not_found' | 'not_closed' } {
  load();
  const session = sessions.get(sessionId);
  if (!session) return { ok: false, error: 'not_found' };
  if (session.status !== 'closed') return { ok: false, error: 'not_closed' };

  const prior = {
    status: session.status,
    closedAt: session.closedAt,
    lastMessageAt: session.lastMessageAt,
    codexAppDispatchLedger: session.codexAppDispatchLedger,
    codexAppGenerationCommits: session.codexAppGenerationCommits,
    queued: session.queued,
    queuedPrompt: session.queuedPrompt,
    queuedCodexAppText: session.queuedCodexAppText,
    queuedCodexAppMessageContext: session.queuedCodexAppMessageContext,
    queuedActivationPending: session.queuedActivationPending,
    queuedActivationToken: session.queuedActivationToken,
    queuedActivationInput: session.queuedActivationInput,
    queuedActivationTurnId: session.queuedActivationTurnId,
    queuedActivationDispatchAttempt: session.queuedActivationDispatchAttempt,
    queuedActivationResume: session.queuedActivationResume,
    queuedActivationTail: session.queuedActivationTail,
    queuedActivationTailNextOrder: session.queuedActivationTailNextOrder,
    pendingRepoSetup: session.pendingRepoSetup,
  };

  session.status = 'active';
  session.closedAt = undefined;
  session.lastMessageAt = new Date().toISOString();
  session.codexAppDispatchLedger = undefined;
  session.codexAppGenerationCommits = undefined;
  session.queued = undefined;
  session.queuedPrompt = undefined;
  session.queuedCodexAppText = undefined;
  session.queuedCodexAppMessageContext = undefined;
  session.queuedActivationPending = undefined;
  session.queuedActivationToken = undefined;
  session.queuedActivationInput = undefined;
  session.queuedActivationTurnId = undefined;
  session.queuedActivationDispatchAttempt = undefined;
  session.queuedActivationResume = undefined;
  session.queuedActivationTail = undefined;
  session.queuedActivationTailNextOrder = undefined;
  session.pendingRepoSetup = undefined;

  try {
    persistRow(session);
  } catch (err) {
    Object.assign(session, prior);
    throw err;
  }
  return { ok: true, session };
}

export function updateSessionPid(sessionId: string, pid: number | null): void {
  load();
  const session = sessions.get(sessionId);
  if (session) {
    session.pid = pid ?? undefined;
    persistRow(session);
  }
}

export function updateSession(session: Session): void {
  load();
  sessions.set(session.sessionId, session);
  persistRow(session);
}

/**
 * Persist one exact Riff follow-up lineage for an active durable owner.
 * The process cache changes only after the durable write succeeds.
 */
export function persistActiveRiffLineageExact(
  sessionId: string,
  taskId: string | null,
  options: {
    expectedCurrentTaskIds?: readonly (string | null)[];
    expectedOwner?: RiffDurableOwner;
  } = {},
): Session {
  load();
  ensureDir();

  const applyChecksAndBuildNext = (durable: Session | undefined): Session => {
    if (!durable || durable.status !== 'active') {
      throw new RiffLineageOwnershipError(
        `cannot persist Riff lineage for non-active session ${sessionId}`,
      );
    }
    const durableTaskId = durable.riffParentTaskId ?? null;
    const expected = options.expectedCurrentTaskIds;
    if (expected && !expected.some(candidate => candidate === durableTaskId)) {
      throw new RiffLineageOwnershipError(
        `Riff lineage compare-and-set failed for ${sessionId} `
        + `(current=${durableTaskId ?? 'none'}, expected=${expected.map(id => id ?? 'none').join('|')})`,
      );
    }
    if (options.expectedOwner && !riffOwnersEqual(riffDurableOwner(durable), options.expectedOwner)) {
      throw new RiffLineageOwnershipError(
        `Riff owner compare-and-set failed for ${sessionId} `
        + `(current=${JSON.stringify(riffDurableOwner(durable))}, `
        + `expected=${JSON.stringify(options.expectedOwner)})`,
      );
    }
    const next: Session = {
      ...durable,
      riffParentTaskId: taskId ?? undefined,
    };
    stripLegacyPendingCardFields(next as unknown as Record<string, unknown>);
    return next;
  };

  const publishToCache = (next: Session): Session => {
    const cached = sessions.get(sessionId);
    if (cached) {
      cached.riffParentTaskId = taskId ?? undefined;
      return cached;
    }
    sessions.set(sessionId, next);
    return next;
  };

  const sqliteResult = withOwnStoreDbIfSqlite((db): Session => {
    const select = db.prepare('SELECT row FROM sessions WHERE session_id = ?');
    let inTxn = false;
    try {
      db.exec('BEGIN IMMEDIATE');
      inTxn = true;
      const hit = select.get(sessionId) as { row: string } | undefined;
      const next = applyChecksAndBuildNext(hit ? JSON.parse(hit.row) as Session : undefined);
      const json = JSON.stringify(next);
      if (json !== hit!.row) {
        testOnlyBeforeRowPersist?.(sessionId);
        db.prepare('UPDATE sessions SET status = ?, row = ? WHERE session_id = ?')
          .run(sessionStatusText(next), json, sessionId);
      }
      db.exec('COMMIT');
      inTxn = false;
      return publishToCache(next);
    } catch (err) {
      if (inTxn) { try { db.exec('ROLLBACK'); } catch { /* txn already gone */ } }
      throw err;
    }
  });
  if (sqliteResult !== undefined) return sqliteResult;

  const fp = getFilePath();
  return withFileLockSync(fp, () => {
    const { raw, parsed } = readExistingSessionsFromDisk(fp);
    const next = applyChecksAndBuildNext(parsed[sessionId]);
    parsed[sessionId] = next;
    const json = JSON.stringify(parsed, null, 2);
    if (json !== raw) {
      const tmpFp = `${fp}.${process.pid}.${randomUUID()}.tmp`;
      writeFileSync(tmpFp, json, 'utf-8');
      renameSync(tmpFp, fp);
    }
    return publishToCache(next);
  });
}

export function listSessions(): Session[] {
  load();
  return [...sessions.values()];
}

/**
 * Cross-file lookup: find every active session attached to a thread, across
 * all bots. Used when a not-yet-initialized bot is mentioned in a thread that
 * another bot has already pinned to a working directory — the new bot inherits
 * the pinned dir instead of re-prompting the user for repo selection.
 *
 * Reads other bots' session stores directly (best-effort) instead of relying
 * on any in-memory state, since each daemon process only owns its own bot.
 */
export function findActiveSessionsByRoot(rootMessageId: string): Session[] {
  return findActiveSessionsMatching(
    s => s.rootMessageId === rootMessageId,
    { rootMessageId },
  );
}

/**
 * Cross-file lookup: find every active chat-scope session for a chat, across
 * all bots. Mirror of findActiveSessionsByRoot for chat-scope (普通群整群一会话):
 * lets a not-yet-initialised bot inherit the workingDir from a peer bot that
 * already has a chat-scope session in the same chat, so a `botmux send
 * --mention <other-bot>` in 普通群 can spawn the second bot without bouncing
 * through the repo-select card.
 *
 * Only returns scope='chat' sessions — thread-scope sessions in the same chat
 * are routed by rootMessageId and not eligible for chat-scope inheritance.
 */
export function findActiveChatScopeSessionsByChat(chatId: string): Session[] {
  return findActiveSessionsMatching(
    s => s.chatId === chatId && s.scope === 'chat',
    { chatScopeChatId: chatId },
  );
}

/**
 * Count active sessions across every bot's on-disk session store. A pure disk
 * read (no in-memory state) so it's correct at daemon startup regardless of
 * which bot owns this process — used by the restart-report DM after a restart.
 */
export function countActiveSessionsOnDisk(dataDir: string = config.session.dataDir): number {
  let names: string[];
  try {
    names = readdirSync(dataDir);
  } catch { return 0; /* missing dir → 0 */ }
  let n = 0;
  for (const ref of storeRefsFromNames(names, dataDir)) {
    try {
      if (ref.kind === 'sqlite') {
        const db = openDbForRead(ref.path);
        try {
          const hit = db.prepare("SELECT COUNT(*) AS n FROM sessions WHERE status = 'active'").get() as { n: number };
          n += hit.n;
        } finally {
          db.close();
        }
      } else {
        const data: Record<string, Session> = JSON.parse(readFileSync(ref.path, 'utf-8'));
        for (const s of Object.values(data)) if (s?.status === 'active') n++;
      }
    } catch (err) {
      if (err instanceof SessionStoreSqliteUnavailableError) throw err;
      continue;
    }
  }
  return n;
}

/**
 * Collect every CLI session identity botmux has ever recorded — across ALL bot
 * stores, ANY status (active or closed). Returns both each session's botmux
 * `sessionId` (which, for claude-family, IS the on-disk jsonl filename since
 * botmux spawns with `--session-id <id>`) and its `cliSessionId` (the
 * CLI-native id after any resume/rotation, e.g. a codex/traex rollout id).
 *
 * Used by `/adopt`'s resume-import discovery to hide sessions botmux already
 * manages — live OR closed — so the picker surfaces only genuinely external
 * sessions (a CLI the user ran standalone). Closed botmux sessions remain
 * resumable via their own session-closed cards.
 */
export function collectBotmuxSessionIdentities(dataDir: string = config.session.dataDir): Set<string> {
  const ids = new Set<string>();
  const add = (s: Session | undefined) => {
    if (!s) return;
    if (s.sessionId) ids.add(s.sessionId);
    if (s.cliSessionId) ids.add(s.cliSessionId);
  };
  // In-memory first (freshest — covers ids not yet flushed to disk).
  load();
  for (const s of sessions.values()) add(s);
  // Then every bot's persisted store (other daemons own their own stores).
  let names: string[];
  try {
    names = readdirSync(dataDir);
  } catch { return ids; /* missing dir → in-memory only */ }
  for (const ref of storeRefsFromNames(names, dataDir)) {
    try {
      for (const [, s] of readStoreEntries(ref)) add(s);
    } catch (err) {
      if (err instanceof SessionStoreSqliteUnavailableError) throw err;
      continue;
    }
  }
  return ids;
}

// ─── Cross-process offline access ───────────────────────────────────────────
// The only sanctioned ways to touch session rows from OUTSIDE the owning
// daemon process (agent-facing CLI subcommands, caller-identity proofs). Until
// 2026-08 the CLI kept its own parallel copies of these (loadSessions /
// saveSession / mutateSessionOffline in cli.ts) — one of which wrote the whole
// file WITHOUT the lock; they were absorbed here so persistence mechanics
// (store layout, lock/transaction, legacy-field strip) stay private to this
// module. Every entry point resolves each store as db-else-json (mixed
// upgrade window: npm already replaced dist, daemon still running old code).

/**
 * Read-only snapshot of every session row across the legacy store and all
 * per-bot stores. Per-bot rows win duplicate sessionIds and get `larkAppId`
 * stamped from their filename so a later offline mutation resolves the owning
 * store. Deliberately lock-free: atomic publication (tmp+rename for JSON,
 * WAL transactions for SQLite) keeps each store self-consistent, and snapshot
 * composition must stay a pure reader (an older CLI opportunistically migrated
 * legacy rows here, which made even `botmux list` a whole-file writer able to
 * race a daemon save).
 */
export function loadAllSessionsSnapshot(options: {
  dataDir?: string;
  /** Per-bot fallback when the data dir cannot be enumerated (the CLI file
   *  sandbox exposes this bot's own store but NOT a listing of data/). */
  fallbackAppId?: string;
} = {}): Map<string, Session> {
  const dataDir = options.dataDir ?? config.session.dataDir;
  const out = new Map<string, Session>();
  const readInto = (ref: StoreFileRef): void => {
    let entries: [string, Session][];
    try {
      entries = readStoreEntries(ref);
    } catch (err) {
      if (err instanceof SessionStoreSqliteUnavailableError) throw err;
      return; /* missing or corrupt store → skip */
    }
    // Arrays are deliberately tolerated on the JSON side (Object.entries
    // yields their rows): the historical CLI loader accepted array-shaped
    // files and existing fixtures/tools rely on that.
    for (const [, value] of entries) {
      const session = value as Session;
      if (!session || typeof session !== 'object' || !session.sessionId) continue;
      repairMissingChatScope(session);
      if (ref.appId && !session.larkAppId) session.larkAppId = ref.appId;
      out.set(session.sessionId, session);
    }
  };
  readInto(resolveStoreFile(undefined, dataDir));
  let names: string[] | undefined;
  try {
    names = readdirSync(dataDir);
  } catch {
    if (options.fallbackAppId) {
      readInto(resolveStoreFile(options.fallbackAppId, dataDir));
    }
    return out;
  }
  for (const ref of storeRefsFromNames(names, dataDir)) {
    if (ref.appId) readInto(ref);
  }
  return out;
}

/**
 * Unlocked point-read of one row straight from disk, bypassing this process's
 * in-memory cache: the owning per-bot store first, then the legacy store.
 * Atomic publication keeps each store self-consistent, so this never blocks
 * on (or throws from) the store lock — safe on hot paths that only need a
 * freshness hint.
 */
export function readSessionRowFromDisk(
  sessionId: string,
  larkAppId?: string,
  dataDir: string = config.session.dataDir,
): Session | undefined {
  const stores = larkAppId
    ? [resolveStoreFile(larkAppId, dataDir), resolveStoreFile(undefined, dataDir)]
    : [resolveStoreFile(undefined, dataDir)];
  for (const ref of stores) {
    if (!existsSync(ref.path)) continue;
    try {
      const hit = readStoreRowByKey(ref, sessionId);
      if (hit) return hit;
    } catch (err) {
      if (err instanceof SessionStoreSqliteUnavailableError) throw err;
      /* ignore corrupt/racing session store */
    }
  }
  return undefined;
}

/**
 * Fail-closed identity scan: every store's copy of one session row across the
 * legacy and all per-bot stores — one entry per store that holds the id (a
 * per-bot store is its .db when that exists, else its .json; a frozen
 * pre-import JSON file is superseded, not a second copy). An unlistable data
 * dir THROWS: a caller proving "this row resolves exactly once" must not
 * mistake an unreadable store for an empty one. A corrupt individual store is
 * skipped: an unrelated bot's bad file must neither block nor impersonate a
 * valid record; the target row still has to resolve from a readable store.
 */
export function readSessionRowCopiesAcrossStores(
  sessionId: string,
  dataDir: string = config.session.dataDir,
): Session[] {
  const names = readdirSync(dataDir);
  const matches: Session[] = [];
  for (const ref of storeRefsFromNames(names, dataDir)) {
    let session: Session | undefined;
    try {
      session = readStoreRowByKey(ref, sessionId);
    } catch (err) {
      if (err instanceof SessionStoreSqliteUnavailableError) throw err;
      continue;
    }
    if (!session || typeof session !== 'object' || Array.isArray(session)) continue;
    if (session.sessionId !== sessionId) continue;
    matches.push(session);
  }
  return matches;
}

/**
 * Locked offline mutation of one exact row in its owning store (per-bot when
 * the caller-observed row carries `larkAppId`, the legacy store otherwise).
 * Re-reads the row under the owning store's write exclusion — the SQLite
 * store's `BEGIN IMMEDIATE` transaction, or the shared file lock for a store
 * still on JSON — and hands the FRESH copy to `mutate`, never publishing the
 * caller's possibly-stale snapshot.
 *
 * `abortIf` is evaluated at entry (inside the exclusion) and re-evaluated
 * immediately before publication; returning true abandons the mutation with
 * `undefined` (callers pass a daemon-liveness probe so an owning daemon that
 * appears mid-flight stays authoritative and the store is left untouched).
 * SQLite's own locking does NOT replace this probe: it orders writers, but
 * cannot detect that a daemon holding a stale in-memory cache has come alive.
 *
 * Returns the fresh row — mutated when `mutate` returned true, otherwise
 * unmodified (so `() => false` is an exclusion-ordered fresh read) — or
 * undefined when the row is absent or `abortIf` aborted.
 */
export function mutateSessionRowOffline(
  target: { sessionId: string; larkAppId?: string },
  mutate: (current: Session) => boolean,
  options: { dataDir?: string; abortIf?: () => boolean } = {},
): Session | undefined {
  const dataDir = options.dataDir ?? config.session.dataDir;
  const ref = resolveStoreFile(target.larkAppId, dataDir);

  if (ref.kind === 'sqlite') {
    const db = openDbForOwnStore(ref.path);
    let inTxn = false;
    try {
      db.exec('BEGIN IMMEDIATE');
      inTxn = true;
      if (options.abortIf?.()) return undefined;
      const hit = db.prepare('SELECT row FROM sessions WHERE session_id = ?')
        .get(target.sessionId) as { row: string } | undefined;
      if (!hit) return undefined;
      const current = JSON.parse(hit.row) as Session;
      if (!mutate(current)) return current;
      stripLegacyPendingCardFields(current as unknown as Record<string, unknown>);
      if (options.abortIf?.()) return undefined;
      db.prepare('UPDATE sessions SET status = ?, row = ? WHERE session_id = ?')
        .run(sessionStatusText(current), JSON.stringify(current), target.sessionId);
      db.exec('COMMIT');
      inTxn = false;
      return current;
    } finally {
      if (inTxn) { try { db.exec('ROLLBACK'); } catch { /* txn already gone */ } }
      db.close();
    }
  }

  const fp = ref.path;
  return withFileLockSync(fp, () => {
    if (options.abortIf?.()) return undefined;
    let data: Record<string, Session> = {};
    if (existsSync(fp)) {
      try { data = JSON.parse(readFileSync(fp, 'utf-8')); } catch { /* start fresh */ }
    }
    const current = data[target.sessionId];
    if (!current || !mutate(current)) return current;
    data[target.sessionId] = current;

    // Clean up entries where the file key doesn't match the entry's sessionId
    // (data corruption), and strip removed placeholder-card fields — the same
    // convergence the daemon's save() applies.
    for (const [key, val] of Object.entries(data)) {
      if (val && typeof val === 'object' && 'sessionId' in val && (val as Session).sessionId !== key) {
        delete data[key];
        continue;
      }
      if (val && typeof val === 'object') stripLegacyPendingCardFields(val as unknown as Record<string, unknown>);
    }

    if (options.abortIf?.()) return undefined;
    const tmpFp = `${fp}.${process.pid}.${randomUUID()}.tmp`;
    writeFileSync(tmpFp, JSON.stringify(data, null, 2), 'utf-8');
    renameSync(tmpFp, fp);
    return current;
  });
}

function findActiveSessionsMatching(
  predicate: (s: Session) => boolean,
  hint?: { rootMessageId?: string; chatScopeChatId?: string },
): Session[] {
  load();
  const matches: Session[] = [];
  for (const s of sessions.values()) {
    if (predicate(s) && s.status === 'active') matches.push(s);
  }
  const dataDir = config.session.dataDir;
  let names: string[];
  try {
    names = readdirSync(dataDir);
  } catch { return matches; }
  for (const ref of storeRefsFromNames(names, dataDir)) {
    if (ref.appId === currentAppId) continue;
    try {
      for (const s of readStoreActiveRows(ref, hint)) {
        if (predicate(s) && s.status === 'active') matches.push(s);
      }
    } catch (err) {
      if (err instanceof SessionStoreSqliteUnavailableError) throw err;
      continue;
    }
  }
  return matches;
}
