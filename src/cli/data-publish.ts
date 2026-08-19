import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { DATA_PUBLISH_CAPABILITY_BASENAME } from '../services/agent-data-publish-relay.js';

function argValue(args: readonly string[], flag: string): string | undefined {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
}

function safeDatasetId(value: string): string {
  if (!/^[a-z][a-z0-9_]{0,127}$/u.test(value)) throw new Error('--dataset-id is invalid');
  return value;
}

function safeRelative(value: string): string {
  if (!value || value.startsWith('/') || value.includes('\\') || value.split('/').some(part => !part || part === '.' || part === '..')) {
    throw new Error('--staging-relative-path must stay below the current session staging root');
  }
  return value;
}

function stagingRelativePath(relativeArg: string | undefined, directoryArg: string | undefined): string {
  if (relativeArg && directoryArg) throw new Error('use only one of --staging-relative-path and --staging-dir');
  if (relativeArg) return safeRelative(relativeArg);
  if (!directoryArg) throw new Error('--staging-dir or --staging-relative-path is required');
  const rootRaw = process.env.BOTMUX_DATA_STAGING_ROOT?.trim();
  if (!rootRaw || !isAbsolute(rootRaw) || rootRaw.includes('\\')) {
    throw new Error('BOTMUX_DATA_STAGING_ROOT is unavailable for --staging-dir');
  }
  if (!isAbsolute(directoryArg) || directoryArg.includes('\\')) {
    throw new Error('--staging-dir must be an absolute POSIX path inside the current session');
  }
  const root = resolve(rootRaw);
  const target = resolve(directoryArg);
  const rel = relative(root, target);
  if (!rel || rel === '..' || rel.startsWith('../') || isAbsolute(rel) || rel.includes('\\')) {
    throw new Error('--staging-dir must stay below BOTMUX_DATA_STAGING_ROOT');
  }
  return safeRelative(rel);
}

/**
 * Ask qlib's file-only publisher to emit the canonical T3 envelope. The
 * capability is read at invocation time, so a container-start environment
 * value can never authorize a later turn. No database connection is exposed
 * to this child process; the host relay remains the only DB writer.
 */
export function runDataPublishCommand(args: readonly string[]): void {
  if ((args[0] ?? '') !== 'submit') throw new Error('usage: botmux data-publish submit --dataset-id <id> --staging-dir <absolute-path>');
  const outbox = process.env.BOTMUX_SEND_RELAY?.trim();
  const sessionId = process.env.BOTMUX_SESSION_ID?.trim();
  const datasetId = argValue(args, '--dataset-id');
  const staging = stagingRelativePath(argValue(args, '--staging-relative-path'), argValue(args, '--staging-dir'));
  if (!outbox || !sessionId) throw new Error('data publish is available only inside a managed sandbox session');
  if (!datasetId) throw new Error('--dataset-id is required');
  const capabilityPath = join(outbox, DATA_PUBLISH_CAPABILITY_BASENAME);
  const capabilityStat = lstatSync(capabilityPath);
  if (!capabilityStat.isFile() || capabilityStat.isSymbolicLink() || capabilityStat.size > 4096) {
    throw new Error('current data-publish capability is unavailable');
  }
  const capability = JSON.parse(readFileSync(capabilityPath, 'utf8')) as Record<string, unknown>;
  if (capability.sessionId !== sessionId || typeof capability.capability !== 'string'
    || typeof capability.turnId !== 'string' || capability.turnId.trim() === '') {
    throw new Error('current data-publish capability is not a valid turn envelope');
  }
  const stagingRoot = process.env.QRANT_SESSION_STAGING_ROOT?.trim();
  const ownerHash = process.env.QRANT_OWNER_OPEN_ID_HASH?.trim();
  const sessionHash = process.env.QRANT_SESSION_HASH?.trim() || process.env.BOTMUX_SESSION_HASH?.trim();
  if (!stagingRoot || !ownerHash || !sessionHash) throw new Error('T3 session identity is unavailable');
  const workspace = process.env.AGENT_WORKSPACE?.trim() || '/workspace';
  const directQlibRoot = join(workspace, 'apps', 'quant-qlib');
  const qlibRoot = existsSync(directQlibRoot) ? directQlibRoot : join(workspace, 'analyze', 'apps', 'quant-qlib');
  const python = String.raw`
import json, os, sys
from src.data_platform.lake_publish import write_publish_outbox_request
request = write_publish_outbox_request(
    dataset_id=sys.argv[1],
    staging_dir=sys.argv[2],
    session_staging_root=os.environ["QRANT_SESSION_STAGING_ROOT"],
    outbox_dir=os.environ["QRANT_SESSION_OUTBOX_DIR"],
    session_hash=os.environ["QRANT_SESSION_HASH"],
    owner_open_id_hash=os.environ["QRANT_OWNER_OPEN_ID_HASH"],
    capability=os.environ["QRANT_PUBLISH_CAPABILITY"],
    turn_id=os.environ["QRANT_TURN_ID"],
)
print(json.dumps({"ok": True, "request_id": request.request_id, "idempotency_key": request.idempotency_key, "status": "queued"}, separators=(",", ":")))
`;
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    QRANT_SESSION_STAGING_ROOT: stagingRoot,
    QRANT_SESSION_OUTBOX_DIR: outbox,
    QRANT_SESSION_HASH: sessionHash,
    QRANT_OWNER_OPEN_ID_HASH: ownerHash,
    QRANT_PUBLISH_CAPABILITY: capability.capability,
    QRANT_TURN_ID: capability.turnId,
    // Explicitly remove any DB URL inherited from a developer shell. The
    // helper is the sandbox-side submit path and must stay filesystem-only.
    QRANT_RESEARCH_DATABASE_URL: undefined,
    DATABASE_URL: undefined,
  };
  const result = spawnSync('uv', ['run', '--project', qlibRoot, 'python', '-c', python, '--', safeDatasetId(datasetId), join(stagingRoot, staging)], {
    cwd: qlibRoot,
    env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error || result.status !== 0) {
    throw new Error('qlib T3 publish request was rejected');
  }
  let output: unknown;
  try { output = JSON.parse(result.stdout.trim()); } catch { throw new Error('qlib T3 publish helper returned invalid status'); }
  if (!output || typeof output !== 'object' || (output as { ok?: unknown }).ok !== true) {
    throw new Error('qlib T3 publish helper returned invalid status');
  }
  process.stdout.write(JSON.stringify(output) + '\n');
}
