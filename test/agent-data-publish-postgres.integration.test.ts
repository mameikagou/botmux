import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Pool } from 'pg';

import {
  createDataPublishCapability,
  DataPublishRelay,
  publishDataCapability,
  readDataPublishCapability,
  type DataPublishCapability,
  type ValidatedDataPublishRequest,
} from '../src/services/agent-data-publish-relay.js';
import { LakePublishHostBridge } from '../src/services/agent-lake-publish-bridge.js';

/**
 * This is deliberately opt-in. The qlib adapter is a real subprocess and the
 * database must be a disposable PostgreSQL instance supplied by the caller.
 * The default qlib root is the checked-out sibling used by this deployment,
 * while BOTMUX_T6_QLIB_ROOT makes the test portable to another checkout.
 */
const qlibRoot = process.env.BOTMUX_T6_QLIB_ROOT?.trim()
  || '/home/admin/mrlonely-code/analyze/apps/quant-qlib';
const databaseUrl = process.env.BOTMUX_AGENT_DATABASE_URL?.trim() || '';
const privateTmpRoot = process.platform === 'linux' ? '/tmp' : tmpdir();
const enabled = process.env.BOTMUX_T6_PG_INTEGRATION === '1'
  && databaseUrl.length > 0
  && existsSync(join(qlibRoot, 'pyproject.toml'));

describe.skipIf(!enabled)('T6 dynamic data-publish PostgreSQL integration', () => {
  const root = join(privateTmpRoot, `botmux-t6-publish-${process.pid}-${randomBytes(6).toString('hex')}`);
  const outboxRoot = join(root, 'outbox');
  const stagingRoot = join(root, 'staging');
  const sessionId = `t6-publish-session-${process.pid}`;
  const ownerOpenIdHash = createHash('sha256').update('t6-publish-owner').digest('hex');
  const sessionHash = createHash('sha256').update(sessionId).digest('hex');
  const pool = new Pool({ connectionString: databaseUrl, max: 2 });
  let currentCapability: DataPublishCapability;
  let bridge: LakePublishHostBridge;
  const bridgeResults: Array<{ readonly jobId: string; readonly status: string }> = [];

  beforeAll(() => {
    mkdirSync(outboxRoot, { recursive: true, mode: 0o700 });
    mkdirSync(stagingRoot, { recursive: true, mode: 0o700 });
    currentCapability = createDataPublishCapability(sessionId, 60_000, Date.now(), {
      turnId: 'turn-1',
      dispatchAttempt: 1,
    });
    publishDataCapability(outboxRoot, currentCapability);
    bridge = new LakePublishHostBridge({ qlibRoot, dsn: databaseUrl });
  });

  afterAll(async () => {
    await pool.end().catch(() => undefined);
    rmSync(root, { recursive: true, force: true });
  });

  function makeStaging(turnId: string): string {
    const requestRoot = join(stagingRoot, turnId, 'request');
    mkdirSync(join(requestRoot, 'payload'), { recursive: true, mode: 0o700 });
    writeFileSync(
      join(requestRoot, 'payload', 'rows.json'),
      JSON.stringify([{ run_id: `${turnId}-run`, row_index: 0, source: 't6-test' }]) + '\n',
      { mode: 0o600 },
    );
    writeFileSync(
      join(requestRoot, 'submission.toml'),
      'dataset_id = "tushare_trade_cal_raw"\nrequested_partitions = ["year=2026"]\n',
      { mode: 0o600 },
    );
    return requestRoot;
  }

  function makeRequest(turnId: string, capability: DataPublishCapability): {
    readonly path: string;
    readonly idempotencyKey: string;
    readonly requestId: string;
  } {
    const stagingPath = makeStaging(turnId);
    const payloadPath = join(stagingPath, 'payload', 'rows.json');
    const payloadHash = createHash('sha256').update(readFileSync(payloadPath)).digest('hex');
    const datasetId = 'tushare_trade_cal_raw';
    const idempotencyKey = createHash('sha256')
      .update(`${sessionHash}${datasetId}${payloadHash}`)
      .digest('hex');
    const requestId = randomUUID();
    const requestPath = join(outboxRoot, `${idempotencyKey}.json`);
    writeFileSync(requestPath, JSON.stringify({
      version: 1,
      kind: 'lake_publish_request',
      request_id: requestId,
      dataset_id: datasetId,
      staging_path: `${turnId}/request`,
      session_hash: sessionHash,
      owner_open_id_hash: ownerOpenIdHash,
      payload_hash: payloadHash,
      base_version_hash: '0'.repeat(64),
      requested_partitions: ['year=2026'],
      partition_base_hashes: { 'year=2026': '0'.repeat(64) },
      idempotency_key: idempotencyKey,
      source: ['t6-postgres-integration'],
      capability: capability.capability,
      turn_id: capability.turnId,
      created_at: new Date().toISOString(),
    }) + '\n', { mode: 0o600 });
    return { path: requestPath, idempotencyKey, requestId };
  }

  function relay(): DataPublishRelay {
    return new DataPublishRelay({
      outboxRoot,
      sessionId,
      sessionStagingRoot: stagingRoot,
      expectedSessionHash: sessionHash,
      expectedOwnerOpenIdHash: ownerOpenIdHash,
      capability: () => currentCapability,
      onRequest: async (request: ValidatedDataPublishRequest) => {
        const result = await bridge.submit({
          request,
          sessionStagingRoot: stagingRoot,
          expectedSessionHash: sessionHash,
          expectedOwnerOpenIdHash: ownerOpenIdHash,
        });
        bridgeResults.push(result);
      },
    });
  }

  it('rejects the old turn capability, then bridges the rotated turn into real PostgreSQL', async () => {
    const turnOne = makeRequest('turn-1', currentCapability);
    const turnTwoCapability = createDataPublishCapability(sessionId, 60_000, Date.now(), {
      turnId: 'turn-2',
      dispatchAttempt: 2,
    });

    // Rotation happens before the watcher sees turn one. The request remains
    // on disk, but the host callback now authorizes only turn two.
    currentCapability = turnTwoCapability;
    publishDataCapability(outboxRoot, currentCapability);
    expect(readDataPublishCapability(outboxRoot)?.turnId).toBe('turn-2');

    const firstRelay = relay();
    expect(await firstRelay.pollOnce()).toBe(0);
    expect(existsSync(`${turnOne.path}.rejected`)).toBe(true);
    expect(bridgeResults).toHaveLength(0);

    // On a fresh disposable database qlib has not migrated its queue yet;
    // either way, there must be no publication row attributable to turn one.
    const beforeTurnTwo = await pool.query<{ name: string | null }>(
      `SELECT to_regclass('public.lake_publish_jobs')::text AS name`,
    );
    if (beforeTurnTwo.rows[0]?.name === 'lake_publish_jobs') {
      const rejectedRows = await pool.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM lake_publish_jobs WHERE session_hash = $1`,
        [sessionHash],
      );
      expect(rejectedRows.rows[0]?.count).toBe('0');
    } else {
      expect(beforeTurnTwo.rows[0]?.name).toBeNull();
    }

    const turnTwo = makeRequest('turn-2', turnTwoCapability);
    const secondRelay = relay();
    expect(await secondRelay.pollOnce()).toBe(1);
    expect(existsSync(`${turnTwo.path}.accepted`)).toBe(true);
    expect(bridgeResults).toHaveLength(1);
    expect(bridgeResults[0]?.status).toBe('QUEUED');

    // The rejected old request never crossed the host bridge. The accepted
    // request is the only row inserted into the disposable qlib queue.
    const rows = await pool.query<{ session_hash: string; idempotency_key: string; job_id: string; staging_path: string }>(
      `SELECT session_hash, idempotency_key, job_id
              , staging_path
         FROM lake_publish_jobs
        WHERE session_hash = $1
        ORDER BY created_at, job_id`,
      [sessionHash],
    );
    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0]).toMatchObject({
      session_hash: sessionHash,
      idempotency_key: turnTwo.idempotencyKey,
      job_id: turnTwo.requestId,
    });
    expect(rows.rows[0]?.staging_path).toContain('.botmux-data-publish-snapshots');
    expect(rows.rows[0]?.staging_path).not.toContain(stagingRoot);
    expect(rows.rows.some(row => row.idempotency_key === turnOne.idempotencyKey)).toBe(false);
  });
});
