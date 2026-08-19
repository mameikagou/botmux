import { describe, expect, it } from 'vitest';
import {
  AgentCredentialProbeError,
  buildAgentCredentialProbePlan,
  probeAgentApiCredential,
} from '../src/services/agent-credential-probe.js';

const base = {
  image: 'registry.example.test/botmux@sha256:' + 'a'.repeat(64),
  apiKey: 'sk-probe-only-secret',
  baseUrl: 'https://api.example.test/v1',
  model: 'probe-model',
};

describe('rootless API credential probe', () => {
  it('uses the fixed harness, rootless no-gateway network and keeps the key out of argv', () => {
    const codex = buildAgentCredentialProbePlan({ ...base, cliId: 'codex' }, 1000, 1000);
    expect(codex.args).toContain('--userns=keep-id');
    expect(codex.args).toContain('--network=pasta:--no-map-gw');
    expect(codex.args).not.toContain('--network=host');
    expect(codex.args.some(value => value.startsWith('--publish=') || value === '--publish' || value === '-p'
      || value.startsWith('-p=') || value.startsWith('--add-host=') || value.includes('host-gateway'))).toBe(false);
    expect(codex.args).toContain('--env=BOTMUX_HARNESS=codex');
    expect(codex.args).toContain('model_providers.botmux_api.wire_api="responses"');
    expect(codex.args).toContain('exec');
    expect(codex.args).not.toContain('codex');
    expect(codex.args.join('\u0000')).not.toContain(base.apiKey);
    expect(codex.env.AGENT_API_KEY).toBe(base.apiKey);

    const claude = buildAgentCredentialProbePlan({ ...base, cliId: 'claude-code' }, 1000, 1000);
    expect(claude.args).toContain('--env=BOTMUX_HARNESS=claude-code');
    expect(claude.args).toContain('--print');
    expect(claude.args).not.toContain('claude');
    expect(claude.args.join('\u0000')).not.toContain(base.apiKey);

    const pi = buildAgentCredentialProbePlan({ ...base, cliId: 'pi' }, 1000, 1000);
    expect(pi.args).toContain('--print');
    expect(pi.args).not.toContain('pi');

    const opencode = buildAgentCredentialProbePlan({ ...base, cliId: 'opencode' }, 1000, 1000);
    expect(opencode.args).toContain('run');
    expect(opencode.args).not.toContain('opencode');
  });

  it('cleans the named container after a successful probe', async () => {
    const calls: Array<{ command: string; args: readonly string[]; env?: Readonly<Record<string, string>> }> = [];
    let cleaned = '';
    await probeAgentApiCredential({ ...base, cliId: 'opencode' }, {
      hostUid: 1000,
      hostGid: 1000,
      timeoutMs: 1500,
      commandRunner: async (command, args, options) => {
        calls.push({ command, args, env: options.env });
        return { status: 0 };
      },
      cleanup: async (_command, containerName) => { cleaned = containerName; },
    });
    expect(calls).toHaveLength(1);
    expect(cleaned).toMatch(/^botmux-credential-probe-[a-f0-9]{24}$/u);
    expect(calls[0]?.args.join('\u0000')).not.toContain(base.apiKey);
    expect(calls[0]?.env?.AGENT_API_KEY).toBe(base.apiKey);
  });

  it('does not pass the API key to cleanup and sanitizes an unsupported harness', async () => {
    let cleanupEnv: Readonly<Record<string, string>> | undefined;
    await expect(probeAgentApiCredential({ ...base, cliId: 'not-a-harness' }, {
      hostUid: 1000,
      hostGid: 1000,
      cleanup: async (_command, _containerName, options) => { cleanupEnv = options.env; },
    })).rejects.toBeInstanceOf(AgentCredentialProbeError);
    expect(cleanupEnv).toBeUndefined();

    await probeAgentApiCredential({ ...base, cliId: 'pi' }, {
      hostUid: 1000,
      hostGid: 1000,
      commandRunner: async () => ({ status: 0 }),
      cleanup: async (_command, _containerName, options) => { cleanupEnv = options.env; },
    });
    expect(cleanupEnv?.AGENT_API_KEY).toBeUndefined();
  });

  it('turns timeout/nonzero probe results into a sanitized error and still cleans up', async () => {
    let cleanupCalls = 0;
    await expect(probeAgentApiCredential({ ...base, cliId: 'pi' }, {
      hostUid: 1000,
      hostGid: 1000,
      commandRunner: async () => ({ status: null, timedOut: true }),
      cleanup: async () => { cleanupCalls += 1; },
    })).rejects.toBeInstanceOf(AgentCredentialProbeError);
    expect(cleanupCalls).toBe(1);
  });

  it('fails closed when an invalid rootless uid would be required', async () => {
    await expect(probeAgentApiCredential({ ...base, cliId: 'codex' }, {
      hostUid: 0,
      hostGid: 0,
      commandRunner: async () => ({ status: 0 }),
      cleanup: async () => undefined,
    })).rejects.toBeInstanceOf(AgentCredentialProbeError);
  });
});
