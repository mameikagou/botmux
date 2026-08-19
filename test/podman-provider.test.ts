import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readlinkSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

import { buildSessionRuntimePaths, parsePodmanExecutionConfig } from '../src/execution/podman-execution.js';
import {
  PodmanExecutionProvider,
  type PodmanCommandResult,
  type PodmanCommandRunner,
} from '../src/execution/podman-provider.js';

function git(command: string, args: readonly string[]): PodmanCommandResult {
  const result = spawnSync(command, [...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: false,
  });
  return {
    status: result.status,
    stdout: typeof result.stdout === 'string' ? result.stdout : '',
    stderr: typeof result.stderr === 'string' ? result.stderr : '',
    error: result.error instanceof Error ? result.error : undefined,
  };
}

function makeFixture() {
  // The default Node tmpdir is a mounted Windows path in this dev shell and
  // silently ignores chmod; use the local Linux filesystem for mode tests and
  // rootless Podman bind mounts.
  const root = mkdtempSync('/tmp/botmux-provider-');
  const sourceRepo = join(root, 'source');
  const dataRoot = join(sourceRepo, 'apps', 'quant-qlib', 'data');
  const knowledgeRoot = join(sourceRepo, 'apps', 'quant-qlib', 'knowledge', 'investment-books');
  mkdirSync(dataRoot, { recursive: true });
  mkdirSync(join(dataRoot, 'staging'), { recursive: true });
  mkdirSync(knowledgeRoot, { recursive: true });
  writeFileSync(join(dataRoot, 'tracked-catalog.txt'), 'mounted data\n');
  writeFileSync(join(knowledgeRoot, 'tracked-book.txt'), 'mounted book\n');
  writeFileSync(join(sourceRepo, 'apps', 'quant-qlib', 'README.md'), 'qlib project\n');
  writeFileSync(join(sourceRepo, 'README.md'), 'fixture\n');
  expect(git('git', ['init', '--initial-branch', 'main', sourceRepo]).status).toBe(0);
  expect(git('git', ['-C', sourceRepo, 'config', 'user.email', 'botmux-test@example.com']).status).toBe(0);
  expect(git('git', ['-C', sourceRepo, 'config', 'user.name', 'botmux test']).status).toBe(0);
  expect(git('git', ['-C', sourceRepo, 'add', '.']).status).toBe(0);
  expect(git('git', ['-C', sourceRepo, 'commit', '-m', 'fixture']).status).toBe(0);
  const config = parsePodmanExecutionConfig({
    type: 'podman',
    image: 'localhost/botmux-quant-dev@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    sourceRepo,
    sourceBranch: 'main',
    runtimeRoot: join(root, 'runtime'),
    credentialCacheRoot: join(root, 'credential-cache'),
    dataRoot,
    knowledgeRoot,
    ownerMemoryGate: '127.0.0.1:18181',
    idleTimeoutMinutes: 60,
    memory: '1g',
    cpus: 1,
  });
  return { root, config };
}

function fakeRunner(calls: string[][]): PodmanCommandRunner {
  return (command, args) => {
    calls.push([command, ...args]);
    if (command === 'podman') {
      if (args[0] === 'container') {
        return { status: 0, stdout: '{"Status":"running","ContainerID":"cid-test"}\n', stderr: '' };
      }
      return { status: 0, stdout: '', stderr: '' };
    }
    return git(command, args);
  };
}

function seedCodexAuth(config: ReturnType<typeof makeFixture>['config'], sessionId: string): string {
  const runtime = buildSessionRuntimePaths(config, { larkAppId: 'cli_test', openId: 'ou_test' }, sessionId);
  mkdirSync(dirname(runtime.codexAuthPath), { recursive: true, mode: 0o700 });
  writeFileSync(runtime.codexAuthPath, JSON.stringify({ tokens: { access_token: 'fixture-token' } }) + '\n', { mode: 0o600 });
  chmodSync(runtime.codexAuthPath, 0o600);
  return runtime.codexAuthPath;
}

describe('PodmanExecutionProvider', () => {
  it('prepares an independent clone once under concurrent first messages', async () => {
    const fixture = makeFixture();
    const calls: string[][] = [];
    const provider = new PodmanExecutionProvider(fixture.config, {
      commandRunner: fakeRunner(calls),
      hostUid: 1000,
      hostGid: 104,
    });
    const input = {
      sessionId: 'session-one',
      cliId: 'claude-code',
      principalBinding: {
        larkAppId: 'cli_test',
        open_id: 'ou_test',
        enabled: true,
        can_openmemory: false,
      },
      credentialBinding: {
        kind: 'api',
        version: 1,
        baseUrl: 'https://api.example.com/v1',
        model: 'test-model',
      },
    } as const;
    const [first, second] = await Promise.all([provider.prepare(input), provider.prepare(input)]);
    expect(first.hostWorkingDir).toBe(second.hostWorkingDir);
    expect(calls.filter(call => call[0] === 'git' && call[1] === 'clone')).toHaveLength(1);
    expect(statSync(first.runtime.sessionRoot).mode & 0o777).toBe(0o700);
    expect(statSync(first.runtime.homeRoot).mode & 0o777).toBe(0o700);
    expect(statSync(first.runtime.stagingRoot).mode & 0o777).toBe(0o700);
    expect(existsSync(join(first.hostWorkingDir, '.git'))).toBe(true);
    expect(readlinkSync(join(first.hostWorkingDir, 'apps/quant-qlib/data'))).toBe('/shared/quant-data');
    expect(readlinkSync(join(first.hostWorkingDir, 'apps/quant-qlib/knowledge/investment-books')))
      .toBe('/knowledge/investment-books');
    expect(first.network.networkOption).toBe('pasta:--no-map-gw');
  });

  it('emits fixed Podman argv, exact T4 mounts, and keeps API secrets out of argv/files', async () => {
    const fixture = makeFixture();
    const provider = new PodmanExecutionProvider(fixture.config, {
      commandRunner: fakeRunner([]),
      checkImage: false,
      hostUid: 1000,
      hostGid: 104,
      hostEnv: {
        PATH: '/usr/bin',
        HOME: '/home/admin',
        OPENAI_API_KEY: 'host-secret-must-not-forward',
      },
    });
    const prepared = await provider.prepare({
      sessionId: 'session-api',
      cliId: 'opencode',
      principalBinding: { larkAppId: 'cli_test', openId: 'ou_test', canOpenMemory: true },
      credentialBinding: {
        credentialKind: 'api',
        credentialVersion: 2,
        baseUrl: 'https://api.example.com/v1',
        model: 'opencode-test',
      },
    });
   const launch = provider.launch(prepared, {
     cliId: 'opencode',
     bin: '/usr/local/bin/opencode',
     args: ['--version'],
     credentialSecret: 'secret-do-not-log',
     runtimeEnv: {
       BOTMUX_CHAT_ID: 'oc_chat_test',
       BOTMUX_LARK_APP_ID: 'cli_test',
     },
   });
    expect(() => provider.launch(prepared, { cliId: 'opencode', bin: 'opencode', args: ['--version'] }))
      .toThrow(/secret is required/);
   const argv = launch.args.join('\n');
    expect(JSON.stringify(prepared)).not.toContain('secret-do-not-log');
   expect(argv).not.toContain('secret-do-not-log');
    expect(argv).toContain('--rm');
    expect(argv).toContain('--userns=keep-id');
    expect(argv).toContain('--network=pasta:--no-map-gw,-T,18181');
    expect(argv).toContain('--add-host=host.containers.internal:127.0.0.1');
    expect(argv).toContain('--add-host=host.docker.internal:127.0.0.1');
    expect(argv).toContain('dst=/shared/quant-data,ro');
    expect(argv).toContain(`src=${prepared.runtime.stagingRoot},dst=/shared/quant-data/staging,rw`);
    expect(argv).toContain('dst=/knowledge/investment-books,ro');
    expect(argv).toContain('dst=/session/outbox,rw');
    expect(argv).toContain('--env=AGENT_API_KEY');
    expect(argv).toContain('--env=BOTMUX_SESSION_ID=session-api');
    expect(argv).toContain('--env=BOTMUX_CHAT_ID=oc_chat_test');
    expect(launch.env.AGENT_API_KEY).toBe('secret-do-not-log');
    expect(launch.env.OPENAI_API_KEY).toBeUndefined();
    expect(readFileSync(prepared.credential.providerConfig!.path, 'utf8')).not.toContain('secret-do-not-log');
    expect(launch.transcriptPaths).toEqual({
      hostSessionHome: prepared.runtime.homeRoot,
      containerSessionHome: '/home/dev/.agent',
      hostTranscriptRoot: prepared.runtime.homeRoot,
      containerTranscriptRoot: '/home/dev',
      hostWorkspaceRoot: prepared.runtime.workspaceRoot,
      containerWorkspaceRoot: '/workspace',
    });
    expect(() => provider.launch(prepared, {
      cliId: 'opencode',
      bin: 'opencode',
      args: ['--version'],
      credentialSecret: 'secret-do-not-log',
      runtimeEnv: { LD_PRELOAD: '/tmp/host-hook.so' },
    })).toThrow(/not allow-listed/);
  });

  it('fails closed without frozen bindings and never falls back to a host CLI', async () => {
    const fixture = makeFixture();
    const provider = new PodmanExecutionProvider(fixture.config, { checkImage: false });
   await expect(provider.prepare({ sessionId: 'missing-binding', cliId: 'codex' }))
     .rejects.toThrow(/binding is required/);
    seedCodexAuth(fixture.config, 'fixed-cli');
   const prepared = await provider.prepare({
      sessionId: 'fixed-cli',
      cliId: 'codex',
      principalBinding: { larkAppId: 'cli_test', openId: 'ou_test' },
      credentialBinding: { kind: 'codex_chatgpt', version: 1 },
    });
    expect(() => provider.launch(prepared, { cliId: 'claude-code', bin: 'claude', args: [] }))
      .toThrow(/cliId mismatch/);
    expect(() => provider.launch(prepared, { cliId: 'codex', bin: 'sh', args: [] }))
      .toThrow(/fixed codex/);
  });

  it('launches Codex API credentials without provisioning or requiring auth.json', async () => {
    const fixture = makeFixture();
    const provider = new PodmanExecutionProvider(fixture.config, {
      commandRunner: fakeRunner([]),
      checkImage: false,
      hostUid: 1000,
      hostGid: 104,
    });
    const prepared = await provider.prepare({
      sessionId: 'codex-api',
      cliId: 'codex',
      principalBinding: { larkAppId: 'cli_test', openId: 'ou_test' },
      credentialBinding: {
        kind: 'api',
        version: 1,
        baseUrl: 'https://api.example.com/v1',
        model: 'codex-api-test',
      },
    });
    expect(existsSync(prepared.runtime.codexAuthPath)).toBe(false);
    expect(prepared.credential.credentialKind).toBe('api');
    const launch = provider.launch(prepared, {
      cliId: 'codex',
      bin: 'codex',
      args: ['--version'],
      credentialSecret: 'codex-api-secret',
    });
    expect(launch.env.OPENAI_API_KEY).toBe('codex-api-secret');
    expect(launch.args).toContain('--env=OPENAI_BASE_URL=https://api.example.com/v1');
    expect(launch.args).toContain('--env=OPENAI_MODEL=codex-api-test');
    const codexConfig = readFileSync(join(prepared.runtime.homeRoot, '.codex', 'config.toml'), 'utf8');
    expect(codexConfig).toContain('model_provider = "botmux_api"');
    expect(codexConfig).toContain('base_url = "https://api.example.com/v1"');
    expect(codexConfig).toContain('env_key = "OPENAI_API_KEY"');
    expect(codexConfig).toContain('wire_api = "responses"');
    expect(codexConfig).not.toContain('codex-api-secret');
    expect(existsSync(prepared.runtime.codexAuthPath)).toBe(false);
  });

 it('stops without deleting runtime and gates destructive deletion', async () => {
   const fixture = makeFixture();
    let syncStopCalls = 0;
  const provider = new PodmanExecutionProvider(fixture.config, {
    commandRunner: fakeRunner([]),
    checkImage: false,
      syncCommandRunner: (_command, args) => { syncStopCalls += 1; expect(args).toEqual(['stop', '--time', '10', expect.any(String)]); },
  });
    seedCodexAuth(fixture.config, 'lifecycle');
   const prepared = await provider.prepare({
      sessionId: 'lifecycle',
      cliId: 'codex',
      principalBinding: { larkAppId: 'cli_test', openId: 'ou_test' },
      credentialBinding: { kind: 'codex_chatgpt', version: 1 },
    });
   expect((await provider.inspect(prepared)).status).toBe('running');
   await provider.stop(prepared);
    provider.stopSyncBestEffort(prepared);
    expect(syncStopCalls).toBe(1);
   expect(existsSync(prepared.runtime.sessionRoot)).toBe(true);
    await expect(provider.destroyRuntime(prepared)).rejects.toThrow(/authorized:true/);
    await provider.destroyRuntime(prepared, { authorized: true });
    expect(existsSync(prepared.runtime.sessionRoot)).toBe(false);
  });

  it('requires a pre-provisioned private, non-empty JSON Codex auth file', async () => {
    const fixture = makeFixture();
    const provider = new PodmanExecutionProvider(fixture.config, { checkImage: false, hostUid: 1000, hostGid: 104 });
    const input = {
      sessionId: 'auth-validation',
      cliId: 'codex',
      principalBinding: { larkAppId: 'cli_test', openId: 'ou_test' },
      credentialBinding: { kind: 'codex_chatgpt', version: 1 },
    } as const;
    const authPath = buildSessionRuntimePaths(
      fixture.config,
      { larkAppId: 'cli_test', openId: 'ou_test' },
      input.sessionId,
    ).codexAuthPath;
    await expect(provider.prepare(input)).rejects.toThrow(/must already exist/);
    expect(existsSync(authPath)).toBe(false);

    mkdirSync(dirname(authPath), { recursive: true, mode: 0o700 });
    writeFileSync(authPath, '{not-json}\n', { mode: 0o600 });
    await expect(provider.prepare(input)).rejects.toThrow(/valid JSON/);
    writeFileSync(authPath, '{}\n', { mode: 0o600 });
    await expect(provider.prepare(input)).rejects.toThrow(/non-empty JSON object/);
    writeFileSync(authPath, JSON.stringify({ tokens: { access_token: 'fixture-token' } }), { mode: 0o644 });
    chmodSync(authPath, 0o644);
    await expect(provider.prepare(input)).rejects.toThrow(/owner only/);

    rmSync(authPath, { force: true });
    const realAuthPath = authPath + '.real';
    writeFileSync(realAuthPath, JSON.stringify({ tokens: { access_token: 'fixture-token' } }), { mode: 0o600 });
    symlinkSync(realAuthPath, authPath);
    await expect(provider.prepare(input)).rejects.toThrow(/regular file/);
    rmSync(authPath, { force: true });
    writeFileSync(authPath, JSON.stringify({ tokens: { access_token: 'fixture-token' } }), { mode: 0o600 });
    chmodSync(authPath, 0o600);
    const prepared = await provider.prepare(input);
    expect(prepared.runtime.codexAuthPath).toBe(authPath);
  });
});
