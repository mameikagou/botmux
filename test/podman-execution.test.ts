import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  buildCredentialInjectionPlan,
  buildPastaNetworkPlan,
  buildPodmanMountPlan,
  buildSessionRuntimePaths,
  fixedBotCliId,
  isCredentialCompatible,
  materializeCredentialEnvironment,
  parsePodmanExecutionConfig,
  principalHash,
  sessionHash,
} from '../src/execution/podman-execution.js';
import { parseBotConfigsFromText } from '../src/bot-registry.js';

const rawConfig = {
  type: 'podman',
  image: 'localhost/botmux-quant-dev@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  sourceRepo: '/srv/analyze',
  sourceBranch: 'main',
  runtimeRoot: '/srv/.botmux/sandbox-runtime',
  credentialCacheRoot: '/srv/.botmux/credential-cache',
  dataRoot: '/srv/analyze/apps/quant-qlib/data',
  knowledgeRoot: '/srv/analyze/apps/quant-qlib/knowledge/investment-books',
  ownerMemoryGate: '127.0.0.1:18181',
  idleTimeoutMinutes: 60,
  memory: '12g',
  cpus: 8,
} as const;

function config() {
  return parsePodmanExecutionConfig(rawConfig);
}

describe('Podman execution config', () => {
  it('strictly parses and canonicalizes the frozen profile', () => {
    const parsed = parsePodmanExecutionConfig({
      ...rawConfig,
      sourceRepo: '/srv//analyze/',
      dataRoot: '/srv/analyze/apps/quant-qlib/data/',
    });
    expect(parsed.sourceRepo).toBe('/srv/analyze');
    expect(parsed.dataRoot).toBe('/srv/analyze/apps/quant-qlib/data');
    expect(parsed.image).toContain('@sha256:');
  });

  it('rejects unknown fields, relative paths, mutable images, and host-network-shaped config', () => {
    expect(() => parsePodmanExecutionConfig({ ...rawConfig, network: 'host' })).toThrow(/unknown field.*network/);
    expect(() => parsePodmanExecutionConfig({ ...rawConfig, sourceRepo: 'analyze' })).toThrow(/sourceRepo.*absolute/);
    expect(() => parsePodmanExecutionConfig({ ...rawConfig, image: 'localhost/botmux-quant-dev:latest' })).toThrow(/digest/);
    expect(() => parsePodmanExecutionConfig({ ...rawConfig, ownerMemoryGate: '127.0.0.1:8181' })).toThrow(/18181/);
  });

  it('rejects traversal and overlapping mount roots', () => {
    expect(() => parsePodmanExecutionConfig({ ...rawConfig, runtimeRoot: '/srv/analyze/runtime' }))
      .toThrow(/runtimeRoot.*sourceRepo/);
    expect(() => parsePodmanExecutionConfig({ ...rawConfig, dataRoot: '/srv/analyze/../brain' }))
      .toThrow(/parent traversal/);
    expect(() => parsePodmanExecutionConfig({
      ...rawConfig,
      knowledgeRoot: '/srv/analyze/apps/quant-qlib/data/books',
    })).toThrow(/dataRoot and knowledgeRoot/);
    expect(() => parsePodmanExecutionConfig({
      ...rawConfig,
      sourceRepo: '/home/admin/mrlonely-code/brain',
      dataRoot: '/home/admin/mrlonely-code/brain/data',
      knowledgeRoot: '/home/admin/mrlonely-code/brain/books',
    })).toThrow(/brain\/OpenMemory|forbidden host root/);
  });

  it('is parsed as part of a bot config without adding a harness lane', () => {
    const [bot] = parseBotConfigsFromText(JSON.stringify([{
      larkAppId: 'cli_app',
      larkAppSecret: 'secret',
      cliId: 'codex',
      execution: rawConfig,
    }]));
    expect(bot?.cliId).toBe('codex');
    expect(bot?.execution?.type).toBe('podman');
    expect(Object.keys(bot ?? {})).not.toContain('harness');
    expect(() => parseBotConfigsFromText(JSON.stringify([{
      larkAppId: 'cli_app', larkAppSecret: 'secret', cliId: 'gemini', execution: rawConfig,
    }]))).toThrow(/requires cliId/);
  });
});

describe('Podman principal/session identity and runtime paths', () => {
  it('uses the frozen app-scoped principal/session hash formulas', () => {
    const principal = { larkAppId: 'cli_app', openId: 'ou_user' } as const;
    const expectedPrincipal = createHash('sha256').update('cli_app:ou_user').digest('hex').slice(0, 24);
    const expectedSession = createHash('sha256').update('cli_app:ou_user:om_session').digest('hex').slice(0, 24);
    expect(principalHash(principal)).toBe(expectedPrincipal);
    expect(principalHash({ larkAppId: 'cli_app', open_id: 'ou_user' })).toBe(expectedPrincipal);
    expect(principalHash('cli_app', 'ou_user')).toBe(expectedPrincipal);
    expect(sessionHash(principal, 'om_session')).toBe(expectedSession);
    expect(sessionHash('cli_app', 'ou_user', 'om_session')).toBe(expectedSession);

    const paths = buildSessionRuntimePaths(config(), principal, 'om_session');
    expect(paths.sessionRoot).toBe(`/srv/.botmux/sandbox-runtime/${expectedPrincipal}/${expectedSession}`);
    expect(paths.workspaceRoot).toBe(`${paths.sessionRoot}/workspace`);
    expect(paths.homeRoot).toBe(`${paths.sessionRoot}/home`);
    expect(paths.outboxRoot).toBe(`${paths.sessionRoot}/outbox`);
    expect(paths.stagingRoot).toBe(`${paths.sessionRoot}/staging`);
    expect(paths.codexAuthPath).toBe(`/srv/.botmux/credential-cache/${expectedPrincipal}/codex/auth.json`);
    expect(paths.sessionRoot).not.toContain('ou_user');
    expect(paths.containerName).toMatch(/^botmux-[0-9a-f]{24}$/u);
  });
});

describe('Podman credential and mount plans', () => {
  it('keeps Codex ChatGPT to one auth.json leaf mount', () => {
    const runtime = buildSessionRuntimePaths(config(), { larkAppId: 'cli_app', openId: 'ou_user' }, 'session');
    const injection = buildCredentialInjectionPlan({
      cliId: 'codex',
      credentialKind: 'codex_chatgpt',
      credentialVersion: 3,
      sessionHome: runtime.homeRoot,
      authPath: runtime.codexAuthPath,
    });
    const mounts = buildPodmanMountPlan(config(), runtime, injection);
    expect(mounts).toHaveLength(7);
    expect(mounts.filter(mount => mount.kind === 'codex-auth')).toEqual([{
      source: runtime.codexAuthPath,
      target: '/home/dev/.codex/auth.json',
      mode: 'rw',
      kind: 'codex-auth',
      singleFile: true,
    }]);
    expect(mounts.filter(mount => mount.mode === 'ro').map(mount => mount.target))
      .toEqual(['/shared/quant-data', '/knowledge/investment-books']);
    expect(mounts.find(mount => mount.kind === 'quant-data-staging')).toEqual({
      source: runtime.stagingRoot,
      target: '/shared/quant-data/staging',
      mode: 'rw',
      kind: 'quant-data-staging',
    });
  });

  it('does not mount official auth files for API credentials', () => {
    const runtime = buildSessionRuntimePaths(config(), { larkAppId: 'cli_app', openId: 'ou_user' }, 'session');
    const injection = buildCredentialInjectionPlan({
      cliId: 'claude-code',
      credentialKind: 'api',
      credentialVersion: 4,
      sessionHome: runtime.homeRoot,
      baseUrl: 'https://api.example.com/v1',
      model: 'claude-sonnet',
    });
    const mounts = buildPodmanMountPlan(config(), runtime, injection);
    expect(mounts.some(mount => mount.kind === 'codex-auth')).toBe(false);
    expect(injection.providerConfig?.path).toBe(`${runtime.homeRoot}/.agent/providers/claude.json`);
    expect(injection.secretEnvVar).toBe('ANTHROPIC_API_KEY');
    expect(JSON.stringify(injection)).not.toContain('sk-test');
    expect(materializeCredentialEnvironment(injection, 'sk-test')).toMatchObject({
      ANTHROPIC_API_KEY: 'sk-test',
      ANTHROPIC_BASE_URL: 'https://api.example.com/v1',
      ANTHROPIC_MODEL: 'claude-sonnet',
    });
  });

  it('uses the Claude API-key contract for every compatible provider', () => {
    const runtime = buildSessionRuntimePaths(config(), { larkAppId: 'cli_app', openId: 'ou_user' }, 'provider-auth');
    const plan = (baseUrl: string) => buildCredentialInjectionPlan({
      cliId: 'claude-code',
      credentialKind: 'api',
      credentialVersion: 1,
      sessionHome: runtime.homeRoot,
      baseUrl,
      model: 'claude-sonnet',
    });

    expect(plan('https://api.deepseek.com/anthropic').secretEnvVar).toBe('ANTHROPIC_API_KEY');
    expect(plan('https://api.kimi.com/coding/').secretEnvVar).toBe('ANTHROPIC_API_KEY');
    expect(plan('https://api.anthropic.com/v1').secretEnvVar).toBe('ANTHROPIC_API_KEY');
  });

  it('enforces fixed bot cliId and credential compatibility', () => {
    expect(fixedBotCliId({ cliId: 'codex' })).toBe('codex');
    expect(() => fixedBotCliId({ cliId: 'codex-app' })).toThrow(/cliId/);
    expect(isCredentialCompatible('codex', 'codex_chatgpt')).toBe(true);
    expect(isCredentialCompatible('claude-code', 'codex_chatgpt')).toBe(false);
    expect(isCredentialCompatible('claude-code', 'api')).toBe(true);
    expect(() => buildCredentialInjectionPlan({
      cliId: 'claude-code', credentialKind: 'codex_chatgpt', credentialVersion: 1,
      sessionHome: '/srv/home', authPath: '/srv/cache/auth.json',
    })).toThrow(/not compatible/);
  });
});

describe('Pasta network plans', () => {
  it('gives friends no host forwarding and pins host aliases to loopback', () => {
    const plan = buildPastaNetworkPlan({ can_openmemory: false });
    expect(plan.pastaArgs).toEqual(['--no-map-gw']);
    expect(plan.networkOption).toBe('pasta:--no-map-gw');
    expect(plan.portForwards).toEqual([]);
    expect(plan.addHosts).toEqual([
      'host.containers.internal:127.0.0.1',
      'host.docker.internal:127.0.0.1',
    ]);
    expect(plan.portForwards.some(forward => forward.hostPort === 8181)).toBe(false);
  });

  it('allows only the owner MemoryGate TCP 18181 exception', () => {
    const plan = buildPastaNetworkPlan({ canOpenMemory: true });
    expect(plan.pastaArgs).toEqual(['--no-map-gw', '-T', '18181']);
    expect(plan.networkOption).toBe('pasta:--no-map-gw,-T,18181');
    expect(plan.portForwards).toEqual([{
      protocol: 'tcp', hostAddress: '127.0.0.1', hostPort: 18181,
      containerPort: 18181, purpose: 'memory-gate',
    }]);
    expect(JSON.stringify(plan)).not.toContain('network host');
    expect(plan.portForwards.some(forward => forward.hostPort === 8181)).toBe(false);
  });
});
