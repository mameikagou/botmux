import { afterEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createDataPublishCapability,
  dataPublishSnapshotRoot,
  DataPublishRelay,
  publishDataCapability,
  type DataPublishCapability,
  type ValidatedDataPublishRequest,
} from '../src/services/agent-data-publish-relay.js';
import { LakePublishHostBridge } from '../src/services/agent-lake-publish-bridge.js';

const dirs: string[] = [];
afterEach(() => { for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true }); });

function setup() {
  const root = mkdtempSync(join(process.platform === 'linux' ? '/tmp' : tmpdir(), 'botmux-relay-'));
  dirs.push(root);
  const outbox = join(root, 'outbox');
  const staging = join(root, 'workspace');
  mkdirSync(outbox, { recursive: true, mode: 0o700 });
  mkdirSync(staging, { recursive: true, mode: 0o700 });
  writeFileSync(join(staging, 'candidate.parquet'), 'payload');
  const claim = createDataPublishCapability('session-a', 60_000);
  publishDataCapability(outbox, claim);
  return { root, outbox, staging, claim };
}

function request(outbox: string, claim: ReturnType<typeof createDataPublishCapability>, overrides: Record<string, unknown> = {}): string {
  const requestId = 'a'.repeat(32);
  writeFileSync(join(outbox, `publish-${requestId}.json`), JSON.stringify({
    requestId,
    datasetId: 'demo',
    stagingRelativePath: 'candidate.parquet',
    capability: claim.capability,
    ...overrides,
  }));
  return requestId;
}

describe('data publish outbox relay', () => {
  it('derives staging/session identity and consumes a valid request exactly once', async () => {
    const { outbox, staging, claim } = setup();
    const received: ValidatedDataPublishRequest[] = [];
    const relay = new DataPublishRelay({
      outboxRoot: outbox,
      sessionId: 'session-a',
      sessionStagingRoot: staging,
      capability: () => claim,
      onRequest: value => { received.push(value); },
    });
    request(outbox, claim);
    expect(await relay.pollOnce()).toBe(1);
    expect(received[0]?.stagingPath).toBe(join(staging, 'candidate.parquet'));
    expect(received[0]?.sessionId).toBe('session-a');
    expect(readFileSync(join(outbox, `publish-${'a'.repeat(32)}.json.accepted`), 'utf8')).toContain('datasetId');
    expect(await relay.pollOnce()).toBe(0);
  });

  it('hands the bridge a private snapshot even when the source is replaced before callback work', async () => {
    const { root, outbox, staging } = setup();
    const t3Claim = createDataPublishCapability('session-a', 60_000, Date.now(), { turnId: 'turn-race' });
    const sourcePath = join(outbox, `${'f'.repeat(64)}.json`);
    const replacementPath = join(root, 'host-owned-replacement.json');
    writeFileSync(replacementPath, JSON.stringify({ malicious: true }), { mode: 0o600 });
    const snapshotRoot = dataPublishSnapshotRoot(outbox);
    let snapshotPath = '';
    const bridge = new LakePublishHostBridge({
      qlibRoot: root,
      dsn: 'postgresql://localhost/test',
      command: 'fake-python',
      run: async input => {
        const adapterInput = JSON.parse(input.stdin) as { request_path: string };
        const forwarded = readFileSync(adapterInput.request_path, 'utf8');
        expect(forwarded).toContain('"dataset_id":"demo"');
        expect(forwarded).not.toContain('malicious');
        return { status: 0, stdout: '{"job_id":"job-snapshot","status":"QUEUED"}\n', stderr: '' };
      },
    });
    const relay = new DataPublishRelay({
      outboxRoot: outbox,
      sessionId: 'session-a',
      sessionStagingRoot: staging,
      expectedSessionHash: 'a'.repeat(64),
      expectedOwnerOpenIdHash: 'b'.repeat(64),
      capability: () => t3Claim,
      onRequest: async request => {
        snapshotPath = request.requestPath;
        expect(request.snapshotRoot).toBe(snapshotRoot);
        expect(request.requestPath.startsWith(`${snapshotRoot}/`)).toBe(true);
        // Simulate a child replacing the source with a symlink immediately as
        // host callback processing begins. The bridge must never follow it.
        rmSync(sourcePath);
        symlinkSync(replacementPath, sourcePath);
        await bridge.submit({
          request,
          sessionStagingRoot: staging,
          expectedSessionHash: 'a'.repeat(64),
          expectedOwnerOpenIdHash: 'b'.repeat(64),
        });
      },
    });
    writeFileSync(sourcePath, JSON.stringify({
      version: 1,
      kind: 'lake_publish_request',
      request_id: '11111111-1111-4111-8111-111111111111',
      dataset_id: 'demo',
      staging_path: 'candidate.parquet',
      session_hash: 'a'.repeat(64),
      owner_open_id_hash: 'b'.repeat(64),
      payload_hash: 'c'.repeat(64),
      base_version_hash: 'd'.repeat(64),
      requested_partitions: ['date=2026-08-19'],
      partition_base_hashes: { 'date=2026-08-19': 'e'.repeat(64) },
      idempotency_key: 'f'.repeat(64),
      source: ['race-test'],
      capability: t3Claim.capability,
      turn_id: 'turn-race',
    }) + '\n', { mode: 0o600 });
    expect(await relay.pollOnce()).toBe(1);
    expect(existsSync(`${sourcePath}.accepted`)).toBe(true);
    expect(snapshotPath).not.toBe('');
    expect(existsSync(snapshotPath)).toBe(false);
  });

  it('keeps a validated T3 staging tree when the child swaps it for a symlink', async () => {
    const { root, outbox, staging } = setup();
    const claim = createDataPublishCapability('session-a', 60_000, Date.now(), { turnId: 'turn-staging-race' });
    const sourcePath = join(staging, 'turn', 'request');
    mkdirSync(join(sourcePath, 'payload'), { recursive: true, mode: 0o700 });
    const originalPayload = '[{"source":"validated-snapshot"}]\n';
    writeFileSync(join(sourcePath, 'payload', 'rows.json'), originalPayload, { mode: 0o600 });
    writeFileSync(join(sourcePath, 'submission.toml'), 'dataset_id = "demo"\n', { mode: 0o600 });
    const payloadHash = createHash('sha256').update(originalPayload).digest('hex');
    const idempotencyKey = 'a'.repeat(64);
    const requestPath = join(outbox, `${idempotencyKey}.json`);
    writeFileSync(requestPath, JSON.stringify({
      version: 1,
      kind: 'lake_publish_request',
      request_id: '22222222-2222-4222-8222-222222222222',
      dataset_id: 'demo',
      staging_path: 'turn/request',
      session_hash: 'a'.repeat(64),
      owner_open_id_hash: 'b'.repeat(64),
      payload_hash: payloadHash,
      base_version_hash: 'c'.repeat(64),
      requested_partitions: ['date=2026-08-19'],
      partition_base_hashes: { 'date=2026-08-19': 'd'.repeat(64) },
      idempotency_key: idempotencyKey,
      source: ['staging-race-test'],
      capability: claim.capability,
      turn_id: claim.turnId,
    }) + '\n', { mode: 0o600 });
    const replacement = join(root, 'replacement-staging');
    mkdirSync(join(replacement, 'payload'), { recursive: true, mode: 0o700 });
    writeFileSync(join(replacement, 'payload', 'rows.json'), '[{"source":"host-target-must-not-be-read"}]\n', { mode: 0o600 });
    writeFileSync(join(replacement, 'submission.toml'), 'dataset_id = "host-target"\n', { mode: 0o600 });
    let seenPayload = '';
    const bridge = new LakePublishHostBridge({
      qlibRoot: root,
      dsn: 'postgresql://localhost/test',
      command: 'fake-python',
      run: async input => {
        const body = JSON.parse(input.stdin) as { session_staging_root: string };
        seenPayload = readFileSync(join(body.session_staging_root, 'turn', 'request', 'payload', 'rows.json'), 'utf8');
        return { status: 0, stdout: '{"job_id":"job-staging-race","status":"QUEUED"}\n', stderr: '' };
      },
    });
    const relay = new DataPublishRelay({
      outboxRoot: outbox,
      sessionId: 'session-a',
      sessionStagingRoot: staging,
      expectedSessionHash: 'a'.repeat(64),
      expectedOwnerOpenIdHash: 'b'.repeat(64),
      capability: () => claim,
      onRequest: async request => {
        rmSync(sourcePath, { recursive: true, force: true });
        symlinkSync(replacement, sourcePath);
        await bridge.submit({
          request,
          sessionStagingRoot: staging,
          expectedSessionHash: 'a'.repeat(64),
          expectedOwnerOpenIdHash: 'b'.repeat(64),
        });
      },
    });
    expect(await relay.pollOnce()).toBe(1);
    expect(seenPayload).toBe(originalPayload);
    expect(existsSync(`${requestPath}.accepted`)).toBe(true);
  });

  it('quarantines the source when the host snapshot directory is a symlink', async () => {
    const { root, outbox, staging, claim } = setup();
    const snapshotRoot = dataPublishSnapshotRoot(outbox);
    symlinkSync(root, snapshotRoot);
    let callbackCalled = false;
    const relay = new DataPublishRelay({
      outboxRoot: outbox,
      sessionId: 'session-a',
      sessionStagingRoot: staging,
      capability: () => claim,
      onRequest: () => { callbackCalled = true; },
    });
    request(outbox, claim);
    expect(await relay.pollOnce()).toBe(0);
    expect(callbackCalled).toBe(false);
    expect(existsSync(join(outbox, `publish-${'a'.repeat(32)}.json.rejected`))).toBe(true);
  });

  it('removes the host snapshot when callback processing fails', async () => {
    const { outbox, staging, claim } = setup();
    let snapshotPath = '';
    const relay = new DataPublishRelay({
      outboxRoot: outbox,
      sessionId: 'session-a',
      sessionStagingRoot: staging,
      capability: () => claim,
      onRequest: requestValue => {
        snapshotPath = requestValue.requestPath;
        throw new Error('simulated bridge failure');
      },
    });
    request(outbox, claim);
    expect(await relay.pollOnce()).toBe(0);
    expect(existsSync(join(outbox, `publish-${'a'.repeat(32)}.json.rejected`))).toBe(true);
    expect(snapshotPath).not.toBe('');
    expect(existsSync(snapshotPath)).toBe(false);
  });

  it('rejects forged identity, stale capability, traversal and symlink payloads', async () => {
    const { outbox, staging, claim } = setup();
    const relay = new DataPublishRelay({
      outboxRoot: outbox,
      sessionId: 'session-a',
      sessionStagingRoot: staging,
      capability: () => claim,
      onRequest: () => { throw new Error('must not publish'); },
    });
    request(outbox, claim, { sessionId: 'session-b' });
    expect(await relay.pollOnce()).toBe(0);
    expect(await import('node:fs').then(fs => fs.existsSync(join(outbox, `publish-${'a'.repeat(32)}.json.rejected`)))).toBe(true);

    const staleId = 'b'.repeat(32);
    request(outbox, { ...claim, capability: 'c'.repeat(64), expiresAt: 1 }, {});
    // request() uses a fixed id, so replace it with a unique stale request.
    const stalePath = join(outbox, `publish-${staleId}.json`);
    rmSync(join(outbox, `publish-${'a'.repeat(32)}.json`), { force: true });
    writeFileSync(stalePath, JSON.stringify({ requestId: staleId, datasetId: 'demo', stagingRelativePath: 'candidate.parquet', capability: 'c'.repeat(64) }));
    expect(await relay.pollOnce()).toBe(0);
    expect((await import('node:fs')).existsSync(`${stalePath}.rejected`)).toBe(true);

    const traversalId = 'd'.repeat(32);
    writeFileSync(join(outbox, `publish-${traversalId}.json`), JSON.stringify({ requestId: traversalId, datasetId: 'demo', stagingRelativePath: '../outside', capability: claim.capability }));
    expect(await relay.pollOnce()).toBe(0);
    expect((await import('node:fs')).existsSync(join(outbox, `publish-${traversalId}.json.rejected`))).toBe(true);

    symlinkSync(join(staging, 'candidate.parquet'), join(staging, 'link.parquet'));
    const symlinkId = 'e'.repeat(32);
    writeFileSync(join(outbox, `publish-${symlinkId}.json`), JSON.stringify({ requestId: symlinkId, datasetId: 'demo', stagingRelativePath: 'link.parquet', capability: claim.capability }));
    expect(await relay.pollOnce()).toBe(0);
    expect((await import('node:fs')).existsSync(join(outbox, `publish-${symlinkId}.json.rejected`))).toBe(true);
  });

  it('accepts the T3 idempotency filename and request directory without trusting caller identity', async () => {
    const { outbox, staging, claim } = setup();
    const requestDir = join(staging, 'request-1');
    mkdirSync(join(requestDir, 'payload'), { recursive: true });
    writeFileSync(join(requestDir, 'payload', 'part.parquet'), 'payload');
    writeFileSync(join(requestDir, 'submission.toml'), 'dataset_id = "demo"\n');
    const idempotencyKey = 'f'.repeat(64);
    const requestPath = join(outbox, `${idempotencyKey}.json`);
    writeFileSync(requestPath, JSON.stringify({
      version: 1,
      kind: 'lake_publish_request',
      request_id: '11111111-1111-4111-8111-111111111111',
      dataset_id: 'demo',
      staging_path: 'request-1',
      session_hash: 'a'.repeat(64),
      owner_open_id_hash: 'b'.repeat(24),
      payload_hash: '239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5',
      base_version_hash: 'd'.repeat(64),
      requested_partitions: ['date=2026-08-19'],
      partition_base_hashes: { 'date=2026-08-19': 'e'.repeat(64) },
      idempotency_key: idempotencyKey,
      source: ['unit-test'],
      capability: claim.capability,
      turn_id: 'turn-1',
      created_at: new Date().toISOString(),
    }));
    const received: ValidatedDataPublishRequest[] = [];
    const relay = new DataPublishRelay({
      outboxRoot: outbox,
      sessionId: 'session-a',
      sessionStagingRoot: staging,
      expectedSessionHash: 'a'.repeat(64),
      expectedOwnerOpenIdHash: 'b'.repeat(24),
      capability: () => ({ ...claim, turnId: 'turn-1' }),
      onRequest: value => { received.push(value); },
    });
    expect(await relay.pollOnce()).toBe(1);
    expect(received[0]?.requestId).toBe('11111111-1111-4111-8111-111111111111');
    expect(received[0]?.idempotencyKey).toBe(idempotencyKey);
    expect(received[0]?.stagingPath).toBe(requestDir);
    expect(received[0]?.sessionId).toBe('session-a');
    expect(readFileSync(`${requestPath}.accepted`, 'utf8')).toContain('owner_open_id_hash');

    const forgedId = '1'.repeat(64);
    writeFileSync(join(outbox, `${forgedId}.json`), JSON.stringify({
      version: 1,
      kind: 'lake_publish_request',
      request_id: '22222222-2222-4222-8222-222222222222',
      dataset_id: 'demo',
      staging_path: 'request-1',
      session_hash: 'f'.repeat(64),
      owner_open_id_hash: 'b'.repeat(24),
      payload_hash: 'c'.repeat(64),
      base_version_hash: 'd'.repeat(64),
      requested_partitions: ['date=2026-08-19'],
      partition_base_hashes: { 'date=2026-08-19': 'e'.repeat(64) },
      idempotency_key: forgedId,
      source: ['unit-test'],
      capability: claim.capability,
      turn_id: 'turn-1',
      created_at: new Date().toISOString(),
    }));
    expect(await relay.pollOnce()).toBe(0);
    expect(readFileSync(`${join(outbox, `${forgedId}.json`)}.rejected`, 'utf8')).toContain('owner_open_id_hash');
  });

  it('passes the host-derived request path and capability to the qlib adapter over stdin', async () => {
    const root = mkdtempSync(join(process.platform === 'linux' ? '/tmp' : tmpdir(), 'botmux-lake-bridge-'));
    dirs.push(root);
    const outbox = join(root, 'outbox');
    const snapshotRoot = dataPublishSnapshotRoot(outbox);
    mkdirSync(outbox, { recursive: true, mode: 0o700 });
    mkdirSync(snapshotRoot, { recursive: true, mode: 0o700 });
    const stagingSnapshotRoot = join(snapshotRoot, 'direct-staging');
    const stagingSnapshotPath = join(stagingSnapshotRoot, 'request-1');
    mkdirSync(stagingSnapshotPath, { recursive: true, mode: 0o700 });
    writeFileSync(join(stagingSnapshotRoot, '.botmux-private-staging'), 'botmux-private-staging-v1\n', { mode: 0o600 });
    chmodSync(stagingSnapshotRoot, 0o700);
    chmodSync(join(stagingSnapshotRoot, '.botmux-private-staging'), 0o600);
    mkdirSync(join(root, 'staging', 'request-1'), { recursive: true, mode: 0o700 });
    const snapshotPath = join(snapshotRoot, 'b'.repeat(64) + '.json');
    writeFileSync(snapshotPath, '{}\n', { mode: 0o600 });
    let stdin = '';
    const bridge = new LakePublishHostBridge({
      qlibRoot: root,
      dsn: 'postgresql://localhost/test',
      command: 'fake-python',
      run: async input => {
        stdin = input.stdin;
        expect(input.args).toContain('-c');
        expect(input.env.QRANT_RESEARCH_DATABASE_URL).toBeUndefined();
        return { status: 0, stdout: '{"job_id":"job-1","status":"QUEUED"}\n', stderr: '' };
      },
    });
    const claim: DataPublishCapability = {
      sessionId: 'session-a', capability: 'a'.repeat(64), issuedAt: 1, expiresAt: Date.now() + 60_000, turnId: 'turn-1',
    };
    const request: ValidatedDataPublishRequest = {
      requestId: '11111111-1111-4111-8111-111111111111',
      idempotencyKey: 'b'.repeat(64),
      datasetId: 'demo',
      stagingPath: join(root, 'staging', 'request-1'),
      stagingSnapshotRoot,
      stagingSnapshotPath,
      requestPath: snapshotPath,
      snapshotRoot,
      capability: claim.capability,
      sessionId: claim.sessionId,
      sessionHash: 'c'.repeat(24),
      ownerOpenIdHash: 'd'.repeat(24),
      turnId: claim.turnId,
    };
    const result = await bridge.submit({
      request,
      sessionStagingRoot: join(root, 'staging'),
      expectedSessionHash: 'c'.repeat(24),
      expectedOwnerOpenIdHash: 'd'.repeat(24),
    });
    expect(result).toEqual({ jobId: 'job-1', status: 'QUEUED' });
    const payload = JSON.parse(stdin) as Record<string, unknown>;
    expect(payload.request_path).not.toBe(request.requestPath);
    expect(payload.session_staging_root).toBe(stagingSnapshotRoot);
    expect(payload.private_staging_root).toBe(stagingSnapshotRoot);
    expect(payload.expected_capability).toBe(claim.capability);
    expect(payload.expected_turn_id).toBe('turn-1');
  });
});
