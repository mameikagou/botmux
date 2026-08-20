import { afterEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

import {
  computeResultPayloadHash,
  createResultPublishCapability,
  ResultPublishRelay,
  resultPublishSnapshotRoot,
} from '../src/services/agent-result-publish-relay.js';
import { ResultPublishHostBridge } from '../src/services/agent-result-publish-bridge.js';

const roots: string[] = [];
const SESSION_HASH = 'a'.repeat(64);
const OWNER_HASH = 'b'.repeat(64);

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function manifestToml(
  claim: ReturnType<typeof createResultPublishCapability>,
  overrides: { readonly sessionHash?: string; readonly ownerHash?: string; readonly turnId?: string; readonly capability?: string; readonly stage?: string } = {},
): string {
  return [
    'version = 1',
    'kind = "research_result_publish_request"',
    '',
    '[envelope]',
    `session_hash = "${overrides.sessionHash ?? SESSION_HASH}"`,
    `owner_open_id_hash = "${overrides.ownerHash ?? OWNER_HASH}"`,
    `turn_id = "${overrides.turnId ?? claim.turnId}"`,
    `capability = "${overrides.capability ?? claim.capability}"`,
    '',
    '[result]',
    'strategy_id = "demo"',
    'strategy_name = "Demo"',
    'run_id = "run-1"',
    'campaign_id = "campaign-1"',
    'market = "a_share"',
    'engine = "research"',
    `data_snapshot_hash = "${'d'.repeat(64)}"`,
    `code_hash = "${'e'.repeat(64)}"`,
    `stage = "${overrides.stage ?? 'experimental'}"`,
    '',
    '[result.metrics]',
    'annualized_return = 0.12',
    '',
    '[[result.artifacts]]',
    'path = "result.json"',
    'kind = "result"',
    'lifecycle = "intermediate_30d"',
    '',
  ].join('\n');
}

function setup() {
  const root = mkdtempSync('/tmp/botmux-result-publish-');
  roots.push(root);
  const outbox = join(root, 'outbox');
  const staging = join(root, 'staging');
  mkdirSync(outbox, { recursive: true, mode: 0o700 });
  mkdirSync(join(staging, 'turn-1', 'payload'), { recursive: true, mode: 0o700 });
  writeFileSync(join(staging, 'turn-1', 'payload', 'result.json'), '{"value":42}\n', { mode: 0o600 });
  const claim = createResultPublishCapability('session-a', 'turn-1', 60_000);
  writeFileSync(join(staging, 'turn-1', 'manifest.toml'), manifestToml(claim), { mode: 0o600 });
  return { root, outbox, staging, claim };
}

function requestBody(input: {
  readonly staging: string;
  readonly claim: ReturnType<typeof createResultPublishCapability>;
  readonly idempotencyKey?: string;
  readonly topLevel?: Record<string, unknown>;
  readonly manifest?: Parameters<typeof manifestToml>[1];
}) {
  const stagingPath = 'turn-1';
  const manifestPath = join(input.staging, stagingPath, 'manifest.toml');
  writeFileSync(manifestPath, manifestToml(input.claim, input.manifest), { mode: 0o600 });
  const payloadHash = computeResultPayloadHash(join(input.staging, stagingPath), manifestPath);
  const manifestHash = createHash('sha256').update(readFileSync(manifestPath)).digest('hex');
  const computedKey = createHash('sha256')
    .update(`${SESSION_HASH}demo run-1`.replace(' ', '') + payloadHash)
    .digest('hex');
  const key = input.idempotencyKey ?? computedKey;
  return {
    version: 1,
    kind: 'research_result_publish_request',
    request_id: key,
    staging_path: stagingPath,
    manifest_path: 'manifest.toml',
    session_hash: SESSION_HASH,
    owner_open_id_hash: OWNER_HASH,
    payload_hash: payloadHash,
    manifest_hash: manifestHash,
    idempotency_key: key,
    capability: input.claim.capability,
    turn_id: input.claim.turnId,
    ...input.topLevel,
  };
}

function writeRequest(outbox: string, key: string, body: unknown): string {
  const path = join(outbox, `${key}.json`);
  writeFileSync(path, JSON.stringify(body) + '\n', { mode: 0o600 });
  return path;
}

function relay(input: ReturnType<typeof setup>, onRequest: (request: any) => Promise<void> | void) {
  return new ResultPublishRelay({
    outboxRoot: input.outbox,
    sessionId: 'session-a',
    sessionStagingRoot: input.staging,
    expectedSessionHash: SESSION_HASH,
    expectedOwnerOpenIdHash: OWNER_HASH,
    capability: () => input.claim,
    onRequest,
  });
}

describe('research-result publish relay', () => {
  it('accepts one strict v1 compat request using host snapshots only', async () => {
    const input = setup();
    const body = requestBody(input);
    const key = body.idempotency_key;
    writeRequest(input.outbox, key, body);
    let received: any;
    const watcher = relay(input, request => {
      received = request;
      expect(readFileSync(request.manifestSnapshotPath, 'utf8')).toContain('strategy_id = "demo"');
      expect(readFileSync(join(request.stagingSnapshotPath, 'payload', 'result.json'), 'utf8')).toContain('42');
      rmSync(join(input.staging, 'turn-1'), { recursive: true, force: true });
      symlinkSync(input.root, join(input.staging, 'turn-1'));
    });
    expect(await watcher.pollOnce()).toBe(1);
    expect(received.stagingPath).toContain(`${input.staging}/turn-1`);
    expect(received.stagingSnapshotPath).toContain(resultPublishSnapshotRoot(input.outbox));
    expect(existsSync(join(input.outbox, `${key}.json.accepted`))).toBe(true);
    expect(existsSync(received.requestPath)).toBe(false);
    expect(existsSync(received.stagingSnapshotRoot)).toBe(false);
  });

  it.each([
    ['session hash', { topLevel: { session_hash: 'f'.repeat(64) } }],
    ['owner hash', { topLevel: { owner_open_id_hash: 'f'.repeat(64) } }],
    ['turn', { topLevel: { turn_id: 'other-turn' } }],
    ['capability', { topLevel: { capability: 'e'.repeat(64) } }],
  ])('rejects forged %s without invoking the consumer', async (_label, override) => {
    const input = setup();
    const body = requestBody({ ...input, ...override });
    const key = body.idempotency_key;
    writeRequest(input.outbox, key, body);
    let called = false;
    const watcher = relay(input, () => { called = true; });
    expect(await watcher.pollOnce()).toBe(0);
    expect(called).toBe(false);
    expect(existsSync(join(input.outbox, `${key}.json.rejected`))).toBe(true);
  });

  it('rejects forbidden DSN/artifact-root/formal-status/python fields', async () => {
    const input = setup();
    const body = requestBody({ ...input, topLevel: { dsn: 'postgresql://secret', artifact_root: '/host/private', formal_status: 'SUCCEEDED', python: 'import os' } });
    const key = body.idempotency_key;
    writeRequest(input.outbox, key, body);
    const watcher = relay(input, () => { throw new Error('must not publish'); });
    expect(await watcher.pollOnce()).toBe(0);
    expect(existsSync(join(input.outbox, `${key}.json.rejected`))).toBe(true);
  });

  it('rejects a guest formal stage and forged manifest envelope', async () => {
    const input = setup();
    const body = requestBody({ ...input, manifest: { stage: 'formal' } });
    const key = body.idempotency_key;
    writeRequest(input.outbox, key, body);
    const watcher = relay(input, () => { throw new Error('must not publish'); });
    expect(await watcher.pollOnce()).toBe(0);
    expect(existsSync(join(input.outbox, `${key}.json.rejected`))).toBe(true);
  });

  it('rejects staging/manifest symlinks and keeps guest paths out of the callback', async () => {
    const input = setup();
    const body = requestBody(input);
    const key = body.idempotency_key;
    rmSync(join(input.staging, 'turn-1', 'payload', 'result.json'));
    symlinkSync('/etc/hosts', join(input.staging, 'turn-1', 'payload', 'result.json'));
    writeRequest(input.outbox, key, body);
    const watcher = relay(input, () => { throw new Error('must not publish'); });
    expect(await watcher.pollOnce()).toBe(0);
    expect(existsSync(join(input.outbox, `${key}.json.rejected`))).toBe(true);
  });

  it('retries a failed bridge without registering a second request', async () => {
    const input = setup();
    const body = requestBody(input);
    const key = body.idempotency_key;
    writeRequest(input.outbox, key, body);
    let calls = 0;
    const watcher = relay(input, () => { calls += 1; if (calls === 1) throw new Error('temporary consumer timeout'); });
    expect(await watcher.pollOnce()).toBe(0);
    expect(existsSync(join(input.outbox, `${key}.json`))).toBe(true);
    await new Promise(resolvePromise => setTimeout(resolvePromise, 510));
    expect(await watcher.pollOnce()).toBe(1);
    expect(calls).toBe(2);
    expect(existsSync(join(input.outbox, `${key}.json.accepted`))).toBe(true);
  });

  it('rejects a different payload reusing an idempotency key', async () => {
    const input = setup();
    const first = requestBody(input);
    const key = first.idempotency_key;
    writeRequest(input.outbox, key, first);
    const watcher = relay(input, () => undefined);
    expect(await watcher.pollOnce()).toBe(1);
    writeFileSync(join(input.staging, 'turn-1', 'payload', 'result.json'), '{"value":99}\n');
    const second = requestBody({ ...input, idempotencyKey: key });
    writeRequest(input.outbox, key, second);
    expect(await watcher.pollOnce()).toBe(0);
    expect(existsSync(join(input.outbox, `${key}.json.rejected`))).toBe(true);
  });

  it('does not accept a replay after the one-shot turn capability was consumed', async () => {
    const input = setup();
    const body = requestBody(input);
    const key = body.idempotency_key;
    const path = writeRequest(input.outbox, key, body);
    const watcher = relay(input, () => undefined);
    expect(await watcher.pollOnce()).toBe(1);
    writeFileSync(path, JSON.stringify(body) + '\n', { mode: 0o600 });
    expect(await watcher.pollOnce()).toBe(0);
    expect(existsSync(`${path}.rejected`)).toBe(true);
  });

  it('rejects executable payloads and non-private request files', async () => {
    const input = setup();
    const body = requestBody(input);
    const key = body.idempotency_key;
    chmodSync(join(input.staging, 'turn-1', 'payload', 'result.json'), 0o700);
    writeRequest(input.outbox, key, body);
    const watcher = relay(input, () => { throw new Error('must not publish'); });
    expect(await watcher.pollOnce()).toBe(0);
    expect(existsSync(join(input.outbox, `${key}.json.rejected`))).toBe(true);
  });
});

describe('research-result host bridge', () => {
  function bridgeFixture() {
    const input = setup();
    const qlibRoot = join(input.root, 'qlib');
    mkdirSync(join(qlibRoot, 'src', 'data_platform'), { recursive: true, mode: 0o700 });
    mkdirSync(join(qlibRoot, 'src', 'result_publish'), { recursive: true, mode: 0o700 });
    writeFileSync(join(qlibRoot, 'pyproject.toml'), '[project]\nname="test"\n', { mode: 0o600 });
    for (const path of [
      join(qlibRoot, 'src', 'data_platform', 'result_publish_core.py'),
      join(qlibRoot, 'src', 'result_publish', 'guest.py'),
      join(qlibRoot, 'src', 'result_publish', 'consumer.py'),
      join(qlibRoot, 'src', 'result_publish', 'cli.py'),
    ]) writeFileSync(path, '# fixed entry\n', { mode: 0o600 });
    return { input, qlibRoot };
  }

  it('uses the fixed compatibility consumer and sanitizes non-zero output', async () => {
    const { input, qlibRoot } = bridgeFixture();
    const body = requestBody(input);
    const key = body.idempotency_key;
    writeRequest(input.outbox, key, body);
    const trustedArtifactRoot = join(input.root, 'trusted-artifacts');
    const bridge = new ResultPublishHostBridge({
      qlibRoot,
      trustedArtifactRoot,
      dsn: 'postgresql://host-secret',
      command: 'fake-python',
      run: async received => {
        expect(received.args.join(' ')).toContain('src.data_platform.result_publish_core');
        const protocol = JSON.parse(received.stdin) as Record<string, unknown>;
        expect(protocol.dsn).toBe('postgresql://host-secret');
        expect(protocol).toHaveProperty('manifest_path');
        expect(protocol.trusted_artifact_root).toBe(trustedArtifactRoot);
        expect(protocol).not.toHaveProperty('artifact_root');
        return { status: 1, stdout: 'secret stdout', stderr: 'secret stderr' };
      },
    });
    const watcher = relay(input, request => bridge.submit({ request, expectedSessionHash: SESSION_HASH, expectedOwnerOpenIdHash: OWNER_HASH }));
    expect(await watcher.pollOnce()).toBe(0);
    expect(existsSync(join(input.outbox, `${key}.json`))).toBe(true);
  });

  it('accepts the bounded compat result and handles timeout without leaking diagnostics', async () => {
    const { input, qlibRoot } = bridgeFixture();
    const body = requestBody(input);
    const key = body.idempotency_key;
    writeRequest(input.outbox, key, body);
    let mode: 'success' | 'timeout' = 'success';
    const bridge = new ResultPublishHostBridge({
      qlibRoot,
      trustedArtifactRoot: join(input.root, 'trusted-artifacts'),
      dsn: 'postgresql://host-secret',
      command: 'fake-python',
      run: async () => mode === 'timeout'
        ? { status: null, stdout: 'dsn=secret', stderr: 'provider secret' }
        : { status: 0, stdout: `{"accepted":true,"ok":true,"registered":true,"result_id":"run-1","idempotency_key":"${key}","status":"SUCCEEDED"}\n`, stderr: '' },
    });
    const watcher = relay(input, request => bridge.submit({ request, expectedSessionHash: SESSION_HASH, expectedOwnerOpenIdHash: OWNER_HASH }));
    expect(await watcher.pollOnce()).toBe(1);
    expect(existsSync(join(input.outbox, `${key}.json.accepted`))).toBe(true);
    mode = 'timeout';
    const second = setup();
    const secondBody = requestBody(second);
    const secondKey = secondBody.idempotency_key;
    writeRequest(second.outbox, secondKey, secondBody);
    const secondWatcher = relay(second, request => bridge.submit({ request, expectedSessionHash: SESSION_HASH, expectedOwnerOpenIdHash: OWNER_HASH }));
    expect(await secondWatcher.pollOnce()).toBe(0);
    expect(existsSync(join(second.outbox, `${secondKey}.json`))).toBe(true);
  });
});
