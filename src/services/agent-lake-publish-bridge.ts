/** Host adapter from the botmux outbox relay to qlib's T3 repository. */
import { spawn } from 'node:child_process';
import { chmodSync, copyFileSync, existsSync, lstatSync, readFileSync, unlinkSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { isAbsolute, relative, resolve } from 'node:path';

import type { ValidatedDataPublishRequest } from './agent-data-publish-relay.js';

const QLIB_SUBMIT_SCRIPT = String.raw`
import json
import sys
from pathlib import Path

from src.data_platform.lake_publish import LakePublishRepository

body = json.load(sys.stdin)
repository = LakePublishRepository(body["dsn"])
job = repository.submit_from_outbox(
    Path(body["request_path"]),
    session_staging_root=Path(body["session_staging_root"]),
    private_staging_root=Path(body["private_staging_root"]),
    expected_session_hash=body["expected_session_hash"],
    expected_owner_open_id_hash=body["expected_owner_open_id_hash"],
    expected_capability=body["expected_capability"],
    expected_turn_id=body["expected_turn_id"],
)
print(json.dumps({"job_id": job.job_id, "status": job.status}, separators=(",", ":")))
`;

export interface LakePublishBridgeResult {
  readonly jobId: string;
  readonly status: string;
}

export interface LakePublishBridgeOptions {
  readonly qlibRoot: string;
  readonly dsn?: string;
  /** Defaults to uv; tests can use a fake executable. */
  readonly command?: string;
  readonly run?: (input: {
    readonly command: string;
    readonly args: readonly string[];
    readonly cwd: string;
    readonly env: NodeJS.ProcessEnv;
    readonly stdin: string;
  }) => Promise<{ readonly status: number | null; readonly stdout: string; readonly stderr: string }>;
}

function safeRoot(value: string): string {
  const root = resolve(value);
  if (!isAbsolute(root) || !existsSync(root)) throw new Error('qlib host adapter is unavailable');
  return root;
}

function defaultRun(input: {
  readonly command: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env: NodeJS.ProcessEnv;
  readonly stdin: string;
}): Promise<{ readonly status: number | null; readonly stdout: string; readonly stderr: string }> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(input.command, [...input.args], {
      cwd: input.cwd,
      env: input.env,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => { stdout += String(chunk); });
    child.stderr.on('data', chunk => { stderr += String(chunk); });
    child.once('error', reject);
    child.once('close', status => resolvePromise({ status, stdout, stderr }));
    child.stdin.end(input.stdin);
  });
}

/**
 * Submit one already-validated request. The qlib process receives its request
 * over stdin, never argv or a writable child environment, and the bridge
 * forwards only the explicit research DB DSN plus normal interpreter paths.
 */
export class LakePublishHostBridge {
  private readonly qlibRoot: string;
  private readonly dsn: string;
  private readonly command: string;
  private readonly run: NonNullable<LakePublishBridgeOptions['run']>;

  constructor(options: LakePublishBridgeOptions) {
    this.qlibRoot = safeRoot(options.qlibRoot);
    this.dsn = options.dsn ?? process.env.QRANT_RESEARCH_DATABASE_URL ?? '';
    if (!this.dsn.trim()) throw new Error('research database is not configured');
    this.command = options.command ?? 'uv';
    this.run = options.run ?? defaultRun;
  }

  async submit(input: {
    readonly request: ValidatedDataPublishRequest;
    readonly sessionStagingRoot: string;
    readonly expectedSessionHash: string;
    readonly expectedOwnerOpenIdHash: string;
  }): Promise<LakePublishBridgeResult> {
    const request = input.request;
    if (!request.requestPath || !request.turnId) {
      throw new Error('data publish request has no trusted turn envelope');
    }
    const stagingSnapshotRoot = resolve(request.stagingSnapshotRoot);
    const stagingSnapshotPath = resolve(request.stagingSnapshotPath);
    const sourceStagingRoot = resolve(input.sessionStagingRoot);
    const sourceStagingPath = resolve(request.stagingPath);
    const sourceRelativePath = relative(sourceStagingRoot, sourceStagingPath);
    if (!sourceRelativePath || sourceRelativePath === '..'
      || sourceRelativePath.startsWith('../') || isAbsolute(sourceRelativePath)) {
      throw new Error('data publish staging path is not a session child');
    }
    const stagingRelativePath = relative(stagingSnapshotRoot, stagingSnapshotPath);
    if (stagingRelativePath !== sourceRelativePath
      || !stagingRelativePath || stagingRelativePath === '..'
      || stagingRelativePath.startsWith('../') || isAbsolute(stagingRelativePath)) {
      throw new Error('data publish staging snapshot does not match the request');
    }
    const snapshotRoot = resolve(request.snapshotRoot);
    const snapshotPath = resolve(request.requestPath);
    const snapshotRelativePath = relative(snapshotRoot, snapshotPath);
    if (!snapshotRelativePath || snapshotRelativePath === '..'
      || snapshotRelativePath.startsWith('../') || isAbsolute(snapshotRelativePath)) {
      throw new Error('data publish request is not a host snapshot');
    }
    const snapshotRootStat = lstatSync(snapshotRoot);
    const snapshotStat = lstatSync(snapshotPath);
    const stagingRootStat = lstatSync(stagingSnapshotRoot);
    const stagingPathStat = lstatSync(stagingSnapshotPath);
    const markerPath = resolve(stagingSnapshotRoot, '.botmux-private-staging');
    const markerStat = lstatSync(markerPath);
    if (!snapshotRootStat.isDirectory() || snapshotRootStat.isSymbolicLink()
      || (snapshotRootStat.mode & 0o777) !== 0o700
      || !snapshotStat.isFile() || snapshotStat.isSymbolicLink()
      || (snapshotStat.mode & 0o777) !== 0o600
      || !stagingRootStat.isDirectory() || stagingRootStat.isSymbolicLink()
      || (stagingRootStat.mode & 0o777) !== 0o700
      || stagingPathStat.isSymbolicLink()
      || !markerStat.isFile() || markerStat.isSymbolicLink()
      || (markerStat.mode & 0o777) !== 0o600
      || readFileSync(markerPath, 'utf8') !== 'botmux-private-staging-v1\n') {
      throw new Error('data publish request snapshot is not a private regular file');
    }
    // DataPublishRelay owns the original outbox file's `.accepted` transition.
    // qlib's repository consumes its input by renaming it, so hand qlib a
    // disposable copy of the host snapshot. The child-writable source path is
    // deliberately absent from this object and is never opened by the bridge.
    const temporaryRequestPath = `${snapshotPath}.${randomUUID()}.json`;
    copyFileSync(snapshotPath, temporaryRequestPath, 0);
    chmodSync(temporaryRequestPath, 0o600);
    const adapterRequestPath = temporaryRequestPath;
    const body = JSON.stringify({
      dsn: this.dsn,
      request_path: adapterRequestPath,
      session_staging_root: stagingSnapshotRoot,
      private_staging_root: stagingSnapshotRoot,
      expected_session_hash: input.expectedSessionHash,
      expected_owner_open_id_hash: input.expectedOwnerOpenIdHash,
      expected_capability: request.capability,
      expected_turn_id: request.turnId,
    });
    const args = this.command === 'uv'
      ? ['run', '--project', this.qlibRoot, 'python', '-c', QLIB_SUBMIT_SCRIPT]
      : ['-c', QLIB_SUBMIT_SCRIPT];
    const inherited = process.env;
    const env: NodeJS.ProcessEnv = {
      PATH: inherited.PATH ?? '/usr/bin:/bin',
      HOME: inherited.HOME ?? '/tmp',
      LANG: inherited.LANG ?? 'C.UTF-8',
      LC_ALL: inherited.LC_ALL ?? 'C.UTF-8',
      PYTHONUNBUFFERED: '1',
    };
    try {
      const result = await this.run({ command: this.command, args, cwd: this.qlibRoot, env, stdin: body });
      if (result.status !== 0) throw new Error('qlib publish adapter rejected the request');
      let parsed: unknown;
      try { parsed = JSON.parse(result.stdout.trim()); } catch { throw new Error('qlib publish adapter returned invalid status'); }
      if (!parsed || typeof parsed !== 'object') throw new Error('qlib publish adapter returned invalid status');
      const row = parsed as Record<string, unknown>;
      if (typeof row.job_id !== 'string' || typeof row.status !== 'string') {
        throw new Error('qlib publish adapter returned invalid status');
      }
      return { jobId: row.job_id, status: row.status };
    } finally {
      if (temporaryRequestPath) {
        try { unlinkSync(temporaryRequestPath); } catch { /* qlib may have renamed it */ }
        try { unlinkSync(`${temporaryRequestPath}.accepted`); } catch { /* already consumed */ }
      }
    }
  }
}
