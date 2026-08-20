import { chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readlinkSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';

import { buildSessionRuntimePaths, parsePodmanExecutionConfig } from '../src/execution/podman-execution.js';
import {
  PodmanExecutionProvider,
  type PodmanCommandResult,
  type PodmanCommandRunner,
} from '../src/execution/podman-provider.js';
import { createMemoryGateCapability } from '../src/services/openmemory-memory-gate.js';

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

  it('joins a frozen sandbox user pod and injects only the host proxy endpoint', async () => {
    const fixture = makeFixture();
    const calls: string[][] = [];
    let podExists = false;
    const podRunner: PodmanCommandRunner = (command, args, options) => {
      if (command !== 'podman') return fakeRunner(calls)(command, args, options);
      calls.push([command, ...args]);
      if (args[0] === 'pod' && args[1] === 'inspect') {
        if (!podExists) return { status: 1, stdout: '', stderr: 'no such pod' };
        const podName = args[args.length - 1]!;
        return {
          status: 0,
          stdout: JSON.stringify({
            Id: 'pod-cid',
            State: { Status: 'Running' },
            Config: { Labels: {
              'io.botmux.managed': 'true',
              'io.botmux.sandbox-user-hash': preparedHash,
              'io.botmux.pod-generation': '4',
              'io.botmux.network-profile': 'guest',
              'io.botmux.proxy-route': 'USA-08',
            } },
          }),
          stderr: '',
        };
      }
      if (args[0] === 'pod' && args[1] === 'create') {
        podExists = true;
        return { status: 0, stdout: '', stderr: '' };
      }
      if (args[0] === 'pod' && (args[1] === 'stop' || args[1] === 'start')) {
        return { status: 0, stdout: '', stderr: '' };
      }
      return { status: 0, stdout: '', stderr: '' };
    };
    // The hash is intentionally calculated by the lifecycle manager's stable
    // sandbox-user identity, not by app-scoped open_id.
    const preparedHash = createHash('sha256').update('stable-user').digest('hex').slice(0, 24);
    const provider = new PodmanExecutionProvider(fixture.config, {
      commandRunner: podRunner,
      checkImage: false,
      hostUid: 1000,
      hostGid: 1000,
      userPodManagerOptions: {
        commandRunner: podRunner,
        syncCommandRunner: () => undefined,
        verifyGuestProxy: false,
        hostEnv: { PATH: '/usr/bin' },
      },
    });
    const prepared = await provider.prepare({
      sessionId: 'user-pod-provider',
      cliId: 'claude-code',
      sandboxUserId: 'stable-user',
      podGeneration: 4,
      principalBinding: { larkAppId: 'cli_test', openId: 'ou_test', enabled: true },
      credentialBinding: {
        kind: 'api',
        version: 1,
        baseUrl: 'https://api.example.com/v1',
        model: 'claude-test',
      },
    });
    expect(prepared.userPod?.podName).toBe(`botmux-user-${preparedHash}-g4`);
    const launch = provider.launch(prepared, {
      cliId: 'claude-code',
      bin: 'claude',
      args: ['--version'],
      credentialSecret: 'api-secret-0123456789abcdef0123456789',
    });
    expect(launch.args).toContain(`--pod=${prepared.userPod?.podName}`);
    expect(launch.args.some(arg => arg.startsWith('--network='))).toBe(false);
    expect(prepared.userPod?.guestProxy).toMatchObject({
      host: '169.254.1.1', httpPort: 17890, socksPort: 17890, selectedRoute: 'USA-08',
    });
    expect(launch.args).toContain('--env=HTTP_PROXY=http://169.254.1.1:17890');
    expect(launch.args).toContain('--env=HTTPS_PROXY=http://169.254.1.1:17890');
    expect(launch.args).toContain('--env=ALL_PROXY=socks5h://169.254.1.1:17890');
    expect(launch.args).toContain('--env=NO_PROXY=127.0.0.1,localhost,::1,host.containers.internal,host.docker.internal');
    expect(launch.args).toContain('--env=http_proxy=http://169.254.1.1:17890');
    expect(launch.args).toContain('--env=https_proxy=http://169.254.1.1:17890');
    expect(launch.args).toContain('--env=all_proxy=socks5h://169.254.1.1:17890');
    expect(launch.args).toContain('--env=no_proxy=127.0.0.1,localhost,::1,host.containers.internal,host.docker.internal');
    expect(launch.args.join('\n')).not.toContain('config.yaml');
    expect(launch.args.join('\n')).not.toContain(':7890');
    const podCreate = calls.find(call => call[0] === 'podman' && call[1] === 'pod' && call[2] === 'create');
    expect(podCreate).toContain('--network=pasta:-T,none,-U,none,--map-host-loopback,169.254.1.1');
    expect(podCreate?.join('\n')).not.toContain(':7890');
    await provider.stop(prepared);
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
      // OpenCode has no frozen remote-MCP contract in this build. Treat this
      // as a friend session and prove it cannot receive the owner forward.
      principalBinding: { larkAppId: 'cli_test', openId: 'ou_test', canOpenMemory: false },
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
     args: ['--system-prompt', 'line one\nline two', ''],
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
    expect(argv).toContain('--interactive');
    expect(argv).toContain('--tty');
    expect(argv).toContain('--userns=keep-id');
    expect(argv).toContain('--pids-limit=512');
    expect(argv).toContain('--memory-swap=1g');
    expect(argv).toContain('--label=io.botmux.resource.memory-bytes=1000000000');
    expect(argv).toContain('--label=io.botmux.resource.cpus=1');
    expect(argv).toContain('--network=pasta:--no-map-gw');
    expect(argv).not.toContain('18181');
    expect(argv).toContain('--add-host=host.containers.internal:127.0.0.1');
    expect(argv).toContain('--add-host=host.docker.internal:127.0.0.1');
    expect(argv).toContain('dst=/shared/quant-data,ro');
    expect(argv).toContain(`src=${prepared.runtime.stagingRoot},dst=/shared/quant-data/staging,rw`);
    expect(argv).toContain('dst=/knowledge/investment-books,ro');
    expect(argv).toContain('dst=/session/outbox,rw');
    expect(argv).toContain('--env=AGENT_API_KEY');
    expect(argv).toContain('--env=BOTMUX_SESSION_ID=session-api');
    expect(argv).toContain('--env=BOTMUX_CHAT_ID=oc_chat_test');
    expect(launch.args.slice(-4)).toEqual(['--', '--system-prompt', 'line one\nline two', '']);
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
    expect(() => provider.launch(prepared, {
      cliId: 'opencode',
      bin: 'opencode',
      args: ['bad\u0000arg'],
      credentialSecret: 'secret-do-not-log',
    })).toThrow(/without NUL/);
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

  it('drops host-only Claude plugins and maps workspace plugins into the container', async () => {
    const fixture = makeFixture();
    const provider = new PodmanExecutionProvider(fixture.config, {
      commandRunner: fakeRunner([]),
      checkImage: false,
      hostUid: 1000,
      hostGid: 104,
    });
    const prepared = await provider.prepare({
      sessionId: 'claude-plugin-map',
      cliId: 'claude-code',
      principalBinding: { larkAppId: 'cli_test', openId: 'ou_test' },
      credentialBinding: {
        kind: 'api',
        version: 1,
        baseUrl: 'https://api.example.com/v1',
        model: 'claude-test',
      },
    });
    const workspacePlugin = join(prepared.hostWorkingDir, '.agent', 'plugin');
    const launch = provider.launch(prepared, {
      cliId: 'claude-code',
      bin: 'claude',
      args: [
        '--plugin-dir', '/home/admin/.botmux/claude-plugin',
        '--plugin-dir', workspacePlugin,
        '--append-system-prompt', 'line one\nline two',
      ],
      credentialSecret: 'claude-api-secret-0123456789abcdef',
    });
    const imageIndex = launch.args.indexOf(fixture.config.image);
    expect(launch.args.slice(imageIndex + 2)).toEqual([
      '--plugin-dir', '/workspace/analyze/.agent/plugin',
      '--append-system-prompt', 'line one\nline two',
    ]);
    expect(launch.args).not.toContain('/home/admin/.botmux/claude-plugin');
  });

  it('seeds Claude onboarding and cwd trust while preserving existing state', async () => {
    const fixture = makeFixture();
    const runtime = buildSessionRuntimePaths(fixture.config, { larkAppId: 'cli_test', openId: 'ou_claude_state' }, 'claude-state');
    const statePath = join(runtime.homeRoot, '.claude.json');
    const claudeStateSecret = 'claude-state-secret-0123456789abcdef';
    mkdirSync(runtime.homeRoot, { recursive: true });
    writeFileSync(statePath, JSON.stringify({
      hasCompletedOnboarding: false,
      mcpServers: { existing: { type: 'http', url: 'https://existing.example/mcp' } },
      customApiKeyResponses: {
        approved: ['previous-approved'],
        rejected: [claudeStateSecret.slice(-20), 'keep-rejected'],
      },
      projects: {
        '/workspace/analyze': { custom: 'keep', hasTrustDialogAccepted: false },
        '/workspace/other': { custom: 'other' },
      },
    }, null, 2));
    const provider = new PodmanExecutionProvider(fixture.config, {
      commandRunner: fakeRunner([]),
      checkImage: false,
      hostUid: 1000,
      hostGid: 1000,
    });
    const prepared = await provider.prepare({
      sessionId: 'claude-state',
      cliId: 'claude-code',
      principalBinding: { larkAppId: 'cli_test', openId: 'ou_claude_state' },
      credentialBinding: {
        kind: 'api',
        version: 1,
        baseUrl: 'https://api.kimi.com/coding/',
        model: 'claude-state-test',
      },
    });
    const state = JSON.parse(readFileSync(statePath, 'utf8')) as {
      hasCompletedOnboarding: boolean;
      mcpServers: Record<string, unknown>;
      projects: Record<string, Record<string, unknown>>;
    };
    expect(state.hasCompletedOnboarding).toBe(true);
    expect(state.mcpServers.existing).toEqual({ type: 'http', url: 'https://existing.example/mcp' });
    expect(state.projects['/workspace/analyze']).toMatchObject({
      custom: 'keep',
      hasTrustDialogAccepted: true,
      hasCompletedProjectOnboarding: true,
    });
    expect(state.projects['/workspace/other']).toEqual({ custom: 'other' });
    const launch = provider.launch(prepared, {
      cliId: 'claude-code',
      bin: 'claude',
      args: ['--version'],
      credentialSecret: claudeStateSecret,
    });
    expect(launch.env.ANTHROPIC_API_KEY).toBe(claudeStateSecret);
    expect(launch.env.ANTHROPIC_AUTH_TOKEN).toBeUndefined();
    expect(launch.args.some(arg => arg.includes('ANTHROPIC_API_KEY'))).toBe(true);
    expect(launch.args.some(arg => arg.includes('ANTHROPIC_AUTH_TOKEN'))).toBe(false);
    const stateAfterLaunch = readFileSync(statePath, 'utf8');
    expect(stateAfterLaunch).not.toContain(claudeStateSecret);
    expect(JSON.parse(stateAfterLaunch)).toMatchObject({
      penguinModeOrgEnabled: true,
      customApiKeyResponses: {
        approved: ['previous-approved', claudeStateSecret.slice(-20)],
        rejected: ['keep-rejected'],
      },
    });
  });

  it('uses DeepSeek API-key auth and writes Claude API-key consent state', async () => {
    const fixture = makeFixture();
    const deepseekSecret = 'deepseek-api-secret-0123456789abcdef';
    const provider = new PodmanExecutionProvider(fixture.config, {
      commandRunner: fakeRunner([]),
      checkImage: false,
      hostUid: 1000,
      hostGid: 1000,
    });
    const prepared = await provider.prepare({
      sessionId: 'claude-deepseek',
      cliId: 'claude-code',
      principalBinding: { larkAppId: 'cli_test', openId: 'ou_deepseek' },
      credentialBinding: {
        kind: 'api',
        version: 1,
        baseUrl: 'https://api.deepseek.com/anthropic',
        model: 'deepseek-chat',
      },
    });
    const launch = provider.launch(prepared, {
      cliId: 'claude-code',
      bin: 'claude',
      args: ['--version'],
      credentialSecret: deepseekSecret,
    });
    expect(launch.env.ANTHROPIC_API_KEY).toBe(deepseekSecret);
    expect(launch.env.ANTHROPIC_AUTH_TOKEN).toBeUndefined();
    expect(launch.args.some(arg => arg.includes('ANTHROPIC_API_KEY'))).toBe(true);
    expect(launch.args.some(arg => arg.includes('ANTHROPIC_AUTH_TOKEN'))).toBe(false);
    const state = JSON.parse(readFileSync(join(prepared.runtime.homeRoot, '.claude.json'), 'utf8')) as Record<string, unknown>;
    expect(state.customApiKeyResponses).toEqual({
      approved: [deepseekSecret.slice(-20)],
      rejected: [],
    });
    expect(state.penguinModeOrgEnabled).toBeUndefined();
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

  it('merges owner MCP config without replacing existing Codex providers', async () => {
    const fixture = makeFixture();
    const sessionId = 'owner-memory-codex';
    const runtime = buildSessionRuntimePaths(fixture.config, { larkAppId: 'cli_test', openId: 'ou_owner' }, sessionId);
    mkdirSync(dirname(runtime.codexAuthPath), { recursive: true, mode: 0o700 });
    writeFileSync(runtime.codexAuthPath, JSON.stringify({ tokens: { access_token: 'fixture-token' } }), { mode: 0o600 });
    mkdirSync(join(runtime.homeRoot, '.codex'), { recursive: true });
    writeFileSync(join(runtime.homeRoot, '.codex', 'config.toml'), [
      'model_provider = "existing"',
      'model = "existing-model"',
      '',
      '[model_providers.existing]',
      'name = "existing"',
      'base_url = "https://existing.example/v1"',
      '',
      '[mcp_servers.other]',
      'url = "https://other.example/mcp"',
      '',
    ].join('\n'));
    const capability = createMemoryGateCapability({
      secret: 'memory-gate-test-secret-0123456789abcdef',
      sessionHash: runtime.sessionHash,
      principalHash: runtime.principalHash,
    });
    const provider = new PodmanExecutionProvider(fixture.config, {
      commandRunner: fakeRunner([]),
      checkImage: false,
      hostUid: 1000,
      hostGid: 1000,
    });
    const prepared = await provider.prepare({
      sessionId,
      cliId: 'codex',
      principalBinding: {
        larkAppId: 'cli_test',
        openId: 'ou_owner',
        enabled: true,
        canOpenMemory: true,
      },
      credentialBinding: {
        kind: 'api',
        version: 1,
        baseUrl: 'https://api.example.com/v1',
        model: 'codex-owner-test',
      },
      memoryGateCapability: capability,
    });
    const configText = readFileSync(join(runtime.homeRoot, '.codex', 'config.toml'), 'utf8');
    expect(configText).toContain('[model_providers.existing]');
    expect(configText).toContain('[mcp_servers.other]');
    expect(configText).toContain('model_provider = "botmux_api"');
    expect(configText).toContain('[model_providers.botmux_api]');
    expect(configText).toContain('base_url = "https://api.example.com/v1"');
    expect(configText).toContain('[mcp_servers.openmemory]');
    expect(configText).toContain('bearer_token_env_var = "BOTMUX_MEMORY_CAPABILITY"');
    expect(configText).not.toContain(capability);
    const launch = provider.launch(prepared, {
      cliId: 'codex',
      bin: 'codex',
      args: ['--version'],
      credentialSecret: 'owner-api-secret',
    });
    expect(launch.args.join('\n')).not.toContain(capability);
    expect(launch.env.BOTMUX_MEMORY_CAPABILITY).toBe(capability);
  });

  it('removes the owner MCP entry when a cold instance is revoked', async () => {
    const fixture = makeFixture();
    const sessionId = 'owner-memory-revoked';
    const runtime = buildSessionRuntimePaths(fixture.config, { larkAppId: 'cli_test', openId: 'ou_owner' }, sessionId);
    mkdirSync(dirname(runtime.codexAuthPath), { recursive: true, mode: 0o700 });
    writeFileSync(runtime.codexAuthPath, JSON.stringify({ tokens: { access_token: 'fixture-token' } }), { mode: 0o600 });
    mkdirSync(join(runtime.homeRoot, '.codex'), { recursive: true });
    writeFileSync(join(runtime.homeRoot, '.codex', 'config.toml'), [
      'model_provider = "existing"',
      'model = "existing-model"',
      '',
      '[model_providers.existing]',
      'name = "existing"',
      'base_url = "https://existing.example/v1"',
      '',
    ].join('\n'));
    const provider = new PodmanExecutionProvider(fixture.config, {
      commandRunner: fakeRunner([]),
      checkImage: false,
      hostUid: 1000,
      hostGid: 1000,
    });
    const capability = createMemoryGateCapability({
      secret: 'memory-gate-test-secret-0123456789abcdef',
      sessionHash: runtime.sessionHash,
      principalHash: runtime.principalHash,
    });
    await provider.prepare({
      sessionId,
      cliId: 'codex',
      principalBinding: { larkAppId: 'cli_test', openId: 'ou_owner', enabled: true, canOpenMemory: true },
      credentialBinding: { kind: 'codex_chatgpt', version: 1 },
      memoryGateCapability: capability,
    });
    const configPath = join(runtime.homeRoot, '.codex', 'config.toml');
    expect(readFileSync(configPath, 'utf8')).toContain('[mcp_servers.openmemory]');
    await provider.prepare({
      sessionId,
      cliId: 'codex',
      principalBinding: { larkAppId: 'cli_test', openId: 'ou_owner', enabled: true, canOpenMemory: false },
      credentialBinding: { kind: 'codex_chatgpt', version: 1 },
    });
    const revokedConfig = readFileSync(configPath, 'utf8');
    expect(revokedConfig).not.toContain('openmemory');
    expect(revokedConfig).not.toContain('18181');
    expect(revokedConfig).not.toContain('BOTMUX_MEMORY_CAPABILITY');
    expect(revokedConfig).toContain('model_provider = "existing"');
    expect(revokedConfig).toContain('model = "existing-model"');
    expect(revokedConfig).toContain('[model_providers.existing]');
  });

  it('merges Claude MCP JSON and expands only the capability env reference', async () => {
    const fixture = makeFixture();
    const sessionId = 'owner-memory-claude';
    const runtime = buildSessionRuntimePaths(fixture.config, { larkAppId: 'cli_test', openId: 'ou_owner' }, sessionId);
    mkdirSync(join(runtime.homeRoot, '.agent'), { recursive: true });
    writeFileSync(join(runtime.homeRoot, '.claude.json'), JSON.stringify({
      theme: 'existing',
      mcpServers: { other: { type: 'http', url: 'https://other.example/mcp' } },
    }, null, 2));
    const capability = createMemoryGateCapability({
      secret: 'memory-gate-test-secret-0123456789abcdef',
      sessionHash: runtime.sessionHash,
      principalHash: runtime.principalHash,
    });
    const provider = new PodmanExecutionProvider(fixture.config, {
      commandRunner: fakeRunner([]),
      checkImage: false,
      hostUid: 1000,
      hostGid: 1000,
    });
    const prepared = await provider.prepare({
      sessionId,
      cliId: 'claude-code',
      principalBinding: { larkAppId: 'cli_test', openId: 'ou_owner', enabled: true, canOpenMemory: true },
      credentialBinding: { kind: 'api', version: 1, baseUrl: 'https://api.example.com/v1', model: 'claude-owner-test' },
      memoryGateCapability: capability,
    });
    const config = JSON.parse(readFileSync(join(runtime.homeRoot, '.claude.json'), 'utf8')) as {
      theme: string;
      mcpServers: Record<string, { url?: string; headers?: Record<string, string> }>;
    };
    expect(config.theme).toBe('existing');
    expect(config.mcpServers.other.url).toBe('https://other.example/mcp');
    expect(config.mcpServers.openmemory.url).toBe('http://127.0.0.1:18181/mcp');
    expect(config.mcpServers.openmemory.headers?.Authorization)
      .toBe('Bearer ${BOTMUX_MEMORY_CAPABILITY}');
    expect(readFileSync(join(runtime.homeRoot, '.claude.json'), 'utf8')).not.toContain(capability);
    const launch = provider.launch(prepared, {
      cliId: 'claude-code',
      bin: 'claude',
      args: ['--version'],
      credentialSecret: 'claude-owner-api-secret-0123456789abcdef',
    });
    expect(launch.args.join('\n')).not.toContain(capability);
    expect(launch.env.BOTMUX_MEMORY_CAPABILITY).toBe(capability);
  });

  it('fails closed on uncontrolled Codex/Claude openmemory name collisions and preserves them on revoke', async () => {
    const fixture = makeFixture();
    const secret = 'memory-gate-test-secret-0123456789abcdef';
    const provider = new PodmanExecutionProvider(fixture.config, {
      commandRunner: fakeRunner([]),
      checkImage: false,
      hostUid: 1000,
      hostGid: 1000,
    });

    const codexSession = 'owner-memory-codex-collision';
    const codexRuntime = buildSessionRuntimePaths(fixture.config, { larkAppId: 'cli_test', openId: 'ou_collision_codex' }, codexSession);
    mkdirSync(join(codexRuntime.homeRoot, '.codex'), { recursive: true });
    const codexCollision = '[mcp_servers.openmemory]\ncommand = "user-owned-openmemory"\n';
    writeFileSync(join(codexRuntime.homeRoot, '.codex', 'config.toml'), codexCollision);
    const codexCapability = createMemoryGateCapability({ secret, sessionHash: codexRuntime.sessionHash, principalHash: codexRuntime.principalHash });
    await expect(provider.prepare({
      sessionId: codexSession,
      cliId: 'codex',
      principalBinding: { larkAppId: 'cli_test', openId: 'ou_collision_codex', enabled: true, canOpenMemory: true },
      credentialBinding: { kind: 'api', version: 1, baseUrl: 'https://api.example.com/v1', model: 'collision-codex' },
      memoryGateCapability: codexCapability,
    })).rejects.toThrow(/uncontrolled name collision/);
    await provider.prepare({
      sessionId: codexSession,
      cliId: 'codex',
      principalBinding: { larkAppId: 'cli_test', openId: 'ou_collision_codex', enabled: true, canOpenMemory: false },
      credentialBinding: { kind: 'api', version: 1, baseUrl: 'https://api.example.com/v1', model: 'collision-codex' },
    });
    expect(readFileSync(join(codexRuntime.homeRoot, '.codex', 'config.toml'), 'utf8')).toContain('command = "user-owned-openmemory"');

    const claudeSession = 'owner-memory-claude-collision';
    const claudeRuntime = buildSessionRuntimePaths(fixture.config, { larkAppId: 'cli_test', openId: 'ou_collision_claude' }, claudeSession);
    mkdirSync(claudeRuntime.homeRoot, { recursive: true });
    const claudeCollision = { mcpServers: { openmemory: { command: 'user-owned-openmemory' } } };
    writeFileSync(join(claudeRuntime.homeRoot, '.claude.json'), `${JSON.stringify(claudeCollision)}\n`);
    const claudeCapability = createMemoryGateCapability({ secret, sessionHash: claudeRuntime.sessionHash, principalHash: claudeRuntime.principalHash });
    await expect(provider.prepare({
      sessionId: claudeSession,
      cliId: 'claude-code',
      principalBinding: { larkAppId: 'cli_test', openId: 'ou_collision_claude', enabled: true, canOpenMemory: true },
      credentialBinding: { kind: 'api', version: 1, baseUrl: 'https://api.example.com/v1', model: 'collision-claude' },
      memoryGateCapability: claudeCapability,
    })).rejects.toThrow(/uncontrolled name collision/);
    await provider.prepare({
      sessionId: claudeSession,
      cliId: 'claude-code',
      principalBinding: { larkAppId: 'cli_test', openId: 'ou_collision_claude', enabled: true, canOpenMemory: false },
      credentialBinding: { kind: 'api', version: 1, baseUrl: 'https://api.example.com/v1', model: 'collision-claude' },
    });
    const preservedClaude = JSON.parse(readFileSync(join(claudeRuntime.homeRoot, '.claude.json'), 'utf8')) as { mcpServers: { openmemory: { command: string } } };
    expect(preservedClaude.mcpServers.openmemory.command).toBe('user-owned-openmemory');
  });
});
