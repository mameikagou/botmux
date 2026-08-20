import { afterEach, describe, expect, it, vi } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

vi.mock('node:child_process', () => ({ spawnSync: vi.fn() }));

import { runResultPublishCommand } from '../src/cli/result-publish.js';
import { deriveResultPublishIdentityHash } from '../src/services/agent-result-publish-relay.js';

const mockedSpawnSync = vi.mocked(spawnSync);
const roots: string[] = [];

afterEach(() => {
  mockedSpawnSync.mockReset();
  vi.restoreAllMocks();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function fixture() {
  const root = mkdtempSync('/tmp/botmux-result-publish-cli-');
  roots.push(root);
  const stagingRoot = join(root, 'staging');
  const requestDir = join(stagingRoot, 'turn-1');
  const outbox = join(root, 'outbox');
  const qlibRoot = join(root, 'workspace', 'apps', 'quant-qlib');
  mkdirSync(join(requestDir, 'payload'), { recursive: true, mode: 0o700 });
  mkdirSync(outbox, { recursive: true, mode: 0o700 });
  mkdirSync(qlibRoot, { recursive: true, mode: 0o700 });
  writeFileSync(join(requestDir, 'manifest.toml'), 'version = 1\nkind = "research_result_publish_request"\n', { mode: 0o600 });
  writeFileSync(join(requestDir, 'payload', 'result.json'), '{"ok":true}\n', { mode: 0o600 });
  writeFileSync(join(qlibRoot, 'pyproject.toml'), '[project]\nname = "fixture"\n', { mode: 0o600 });
  writeFileSync(join(outbox, '.botmux-result-publish-capability.json'), JSON.stringify({
    sessionId: 'session-a',
    capability: 'c'.repeat(64),
    turnId: 'turn-1',
    issuedAt: Date.now(),
    expiresAt: Date.now() + 60_000,
  }), { mode: 0o600 });
  return { root, stagingRoot, requestDir, outbox, qlibRoot };
}

describe('result-publish guest CLI', () => {
  it('pins the compatibility submit argv and forwards only file-only envelope values', () => {
    const input = fixture();
    const previous = { ...process.env };
    Object.assign(process.env, {
      AGENT_WORKSPACE: join(input.root, 'workspace'),
      BOTMUX_RESULT_PUBLISH_RELAY: input.outbox,
      BOTMUX_SESSION_ID: 'session-a',
      QRANT_SESSION_STAGING_ROOT: input.stagingRoot,
      QRANT_SESSION_HASH: 'a'.repeat(24),
      QRANT_OWNER_OPEN_ID_HASH: 'b'.repeat(24),
      QRANT_RESEARCH_DATABASE_URL: 'postgresql://should-not-cross',
      QRANT_FRONTEND_API_TOKEN: 'frontend-secret',
      PGPASSWORD: 'secret',
    });
    const output = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    mockedSpawnSync.mockReturnValue({
      status: 0,
      signal: null,
      stdout: '{"accepted":true,"status":"queued"}\n',
      stderr: '',
      error: undefined,
    } as ReturnType<typeof spawnSync>);

    try {
      runResultPublishCommand([
        'submit',
        '--manifest', 'manifest.toml',
        '--staging-dir', input.requestDir,
      ]);
      const call = mockedSpawnSync.mock.calls[0];
      expect(call?.[0]).toBe('uv');
      expect(call?.[1]).toEqual([
        'run', '--project', input.qlibRoot, 'qrant-qlib', 'result', 'publish', 'submit',
        '--manifest', join(input.requestDir, 'manifest.toml'),
        '--staging-dir', input.requestDir,
      ]);
      const options = call?.[2] as { cwd: string; env: NodeJS.ProcessEnv };
      expect(options.cwd).toBe(input.qlibRoot);
      expect(options.env.QRANT_RESULT_PUBLISH_CAPABILITY).toBe('c'.repeat(64));
      expect(options.env.QRANT_SESSION_HASH).toBe(deriveResultPublishIdentityHash('a'.repeat(24)));
      expect(options.env.QRANT_OWNER_OPEN_ID_HASH).toBe(deriveResultPublishIdentityHash('b'.repeat(24)));
      expect(options.env.QRANT_RESEARCH_DATABASE_URL).toBeUndefined();
      expect(options.env.QRANT_FRONTEND_API_TOKEN).toBeUndefined();
      expect(options.env.PGPASSWORD).toBeUndefined();
      expect(output).toHaveBeenCalledWith('{"accepted":true,"status":"queued"}\n');
    } finally {
      for (const key of Object.keys(process.env)) {
        if (!(key in previous)) delete process.env[key];
      }
      Object.assign(process.env, previous);
    }
  });

  it('rejects a manifest outside the staged request before invoking qlib', () => {
    const input = fixture();
    const previous = { ...process.env };
    Object.assign(process.env, {
      AGENT_WORKSPACE: join(input.root, 'workspace'),
      BOTMUX_RESULT_PUBLISH_RELAY: input.outbox,
      BOTMUX_SESSION_ID: 'session-a',
      QRANT_SESSION_STAGING_ROOT: input.stagingRoot,
      QRANT_SESSION_HASH: 'a'.repeat(24),
      QRANT_OWNER_OPEN_ID_HASH: 'b'.repeat(24),
    });
    const outside = join(input.root, 'outside.toml');
    writeFileSync(outside, 'version = 1\n', { mode: 0o600 });
    try {
      expect(() => runResultPublishCommand([
        'submit', '--manifest', outside, '--staging-dir', input.requestDir,
      ])).toThrow('--manifest must stay inside --staging-dir');
      expect(mockedSpawnSync).not.toHaveBeenCalled();
    } finally {
      for (const key of Object.keys(process.env)) {
        if (!(key in previous)) delete process.env[key];
      }
      Object.assign(process.env, previous);
    }
  });
});
