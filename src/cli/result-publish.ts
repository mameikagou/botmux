import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, readFileSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import {
  deriveResultPublishIdentityHash,
  RESULT_PUBLISH_CAPABILITY_BASENAME,
} from '../services/agent-result-publish-relay.js';

const RESULT_PUBLISH_CLI = 'qrant-qlib';

function flagValue(args: readonly string[], flag: string): string | undefined {
  const indexes: number[] = [];
  args.forEach((value, index) => { if (value === flag) indexes.push(index); });
  if (indexes.length > 1) throw new Error(`${flag} may only be supplied once`);
  const index = indexes[0];
  if (index === undefined) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`${flag} requires a value`);
  return value;
}

function safeRelative(value: string, name: string): string {
  if (!value || value.includes('\0') || value.includes('\\') || isAbsolute(value)) {
    throw new Error(`${name} must be a relative POSIX path`);
  }
  const normalized = value.trim();
  if (!normalized || normalized.split('/').some(part => !part || part === '.' || part === '..')) {
    throw new Error(`${name} contains traversal`);
  }
  return normalized;
}

function findStagingRoot(): string {
  const root = process.env.BOTMUX_RESULT_STAGING_ROOT?.trim()
    || process.env.BOTMUX_DATA_STAGING_ROOT?.trim()
    || process.env.QRANT_SESSION_STAGING_ROOT?.trim();
  if (!root || !isAbsolute(root) || root.includes('\\')) {
    throw new Error('result-publish staging root is unavailable for --staging-dir');
  }
  return resolve(root);
}

function stagingRelativePath(stagingArg: string): { readonly root: string; readonly absolute: string; readonly relative: string } {
  if (!isAbsolute(stagingArg) || stagingArg.includes('\\')) {
    throw new Error('--staging-dir must be an absolute POSIX path inside the current session');
  }
  const root = findStagingRoot();
  const absolute = resolve(stagingArg);
  const relativePath = relative(root, absolute);
  if (!relativePath || relativePath === '..' || relativePath.startsWith('../') || isAbsolute(relativePath) || relativePath.includes('\\')) {
    throw new Error('--staging-dir must stay below the current session staging root');
  }
  return { root, absolute, relative: safeRelative(relativePath, '--staging-dir') };
}

function assertRegularDirectory(path: string, label: string): void {
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`${label} must be a real directory`);
}

function assertRegularFile(path: string, label: string): void {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 128 * 1024) throw new Error(`${label} must be a small regular file`);
}

function qlibRoot(): string {
  const workspace = process.env.AGENT_WORKSPACE?.trim() || '/workspace';
  if (!isAbsolute(workspace) || workspace.includes('\\')) throw new Error('result-publish workspace is unavailable');
  const direct = join(workspace, 'apps', 'quant-qlib');
  const nested = join(workspace, 'analyze', 'apps', 'quant-qlib');
  const root = existsSync(join(direct, 'pyproject.toml')) ? direct : nested;
  assertRegularDirectory(root, 'fixed qlib root');
  return root;
}

/**
 * Guest-facing result publication entrypoint.  The Python qlib CLI owns
 * manifest parsing and envelope construction; BotMux only pins the project,
 * reads the one-turn capability, and forwards the two user paths.
 */
export function runResultPublishCommand(args: readonly string[]): void {
  if ((args[0] ?? '') !== 'submit') {
    throw new Error('usage: botmux result-publish submit --manifest <path> --staging-dir <absolute-path>');
  }
  const manifestArg = flagValue(args, '--manifest');
  const stagingArg = flagValue(args, '--staging-dir');
  if (!manifestArg) throw new Error('--manifest is required');
  if (!stagingArg) throw new Error('--staging-dir is required');
  const known = new Set(['submit', '--manifest', manifestArg, '--staging-dir', stagingArg]);
  for (const token of args) {
    if (!known.has(token)) throw new Error(`unknown result-publish argument: ${token}`);
  }
  const outbox = process.env.BOTMUX_RESULT_PUBLISH_RELAY?.trim() || process.env.BOTMUX_SEND_RELAY?.trim();
  const sessionId = process.env.BOTMUX_SESSION_ID?.trim();
  if (!outbox || !sessionId) throw new Error('result-publish is available only inside a managed guest session');
  if (!isAbsolute(outbox) || outbox.includes('\\')) throw new Error('result-publish relay is unavailable');
  assertRegularDirectory(outbox, 'result-publish relay');
  const staging = stagingRelativePath(stagingArg);
  assertRegularDirectory(staging.absolute, '--staging-dir');
  // The compatibility qlib submitter intentionally accepts only a manifest
  // child of the staged request.  The host relay snapshots that file and
  // never trusts the guest-provided path after this point.
  const manifest = isAbsolute(manifestArg)
    ? resolve(manifestArg)
    : resolve(staging.absolute, safeRelative(manifestArg, '--manifest'));
  const manifestRel = relative(staging.absolute, manifest);
  if (!manifestRel || manifestRel === '..' || manifestRel.startsWith('../') || isAbsolute(manifestRel)) {
    throw new Error('--manifest must stay inside --staging-dir');
  }
  assertRegularFile(manifest, '--manifest');

  const capabilityPath = join(outbox, RESULT_PUBLISH_CAPABILITY_BASENAME);
  assertRegularFile(capabilityPath, 'current result-publish capability');
  const capability = JSON.parse(readFileSync(capabilityPath, 'utf8')) as Record<string, unknown>;
  if (capability.sessionId !== sessionId || typeof capability.capability !== 'string'
    || !/^[a-f0-9]{64}$/iu.test(capability.capability)
    || typeof capability.turnId !== 'string' || capability.turnId.trim() === ''
    || typeof capability.expiresAt !== 'number' || capability.expiresAt <= Date.now()) {
    throw new Error('current result-publish capability is not a valid turn envelope');
  }
  const sessionHash = process.env.QRANT_SESSION_HASH?.trim() || process.env.BOTMUX_SESSION_HASH?.trim();
  const ownerHash = process.env.QRANT_OWNER_OPEN_ID_HASH?.trim();
  if (!sessionHash || !ownerHash) throw new Error('result-publish session identity is unavailable');
  // Data-publish keeps its existing 24-character runtime envelope.  The
  // result compatibility consumer requires a full digest, so only this child
  // process receives the domain-separated result identity.
  const resultSessionHash = /^[a-f0-9]{64}$/iu.test(sessionHash)
    ? sessionHash
    : deriveResultPublishIdentityHash(sessionHash);
  const resultOwnerHash = /^[a-f0-9]{64}$/iu.test(ownerHash)
    ? ownerHash
    : deriveResultPublishIdentityHash(ownerHash);
  const root = qlibRoot();
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    QRANT_SESSION_STAGING_ROOT: staging.root,
    QRANT_SESSION_OUTBOX_DIR: outbox,
    QRANT_SESSION_HASH: resultSessionHash,
    QRANT_OWNER_OPEN_ID_HASH: resultOwnerHash,
    QRANT_RESULT_PUBLISH_CAPABILITY: capability.capability,
    QRANT_PUBLISH_CAPABILITY: capability.capability,
    QRANT_TURN_ID: capability.turnId,
    // Explicitly remove database/DSN values inherited from a developer shell.
    // This process is the guest-side file-only submitter, not the host consumer.
    QRANT_RESEARCH_DATABASE_URL: undefined,
    QRANT_FRONTEND_API_TOKEN: undefined,
    DATABASE_URL: undefined,
    PGHOST: undefined,
    PGPORT: undefined,
    PGUSER: undefined,
    PGPASSWORD: undefined,
    PGDATABASE: undefined,
    PYTHONPATH: undefined,
    PYTHONHOME: undefined,
    PYTHON: undefined,
    VIRTUAL_ENV: undefined,
    UV_PROJECT_ENVIRONMENT: undefined,
    UV_PYTHON: undefined,
  };
  const result = spawnSync('uv', [
    'run', '--project', root, RESULT_PUBLISH_CLI, 'result', 'publish', 'submit',
    '--manifest', manifest,
    '--staging-dir', staging.absolute,
  ], {
    cwd: root,
    env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error || result.status !== 0) throw new Error('qlib result-publish submit was rejected');
  let output: unknown;
  try { output = JSON.parse(result.stdout.trim()); } catch { throw new Error('qlib result-publish helper returned invalid status'); }
  if (!output || typeof output !== 'object' || Array.isArray(output)) throw new Error('qlib result-publish helper returned invalid status');
  const row = output as Record<string, unknown>;
  if (row.ok !== true && row.accepted !== true && row.status !== 'queued') throw new Error('qlib result-publish helper returned invalid status');
  const safeOutput: Record<string, unknown> = {};
  for (const key of ['ok', 'accepted', 'request_id', 'idempotency_key', 'result_id', 'status']) {
    const value = row[key];
    if (typeof value === 'string' && value.length <= 256) safeOutput[key] = value;
    else if (typeof value === 'boolean') safeOutput[key] = value;
  }
  process.stdout.write(JSON.stringify(safeOutput) + '\n');
}
