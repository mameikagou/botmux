import {
  MEMORY_GATE_CAPABILITY_ENV,
  MEMORY_GATE_URL,
} from '../services/openmemory-memory-gate.js';

export const BOTMUX_EXECUTION_MODE_ENV = 'BOTMUX_EXECUTION_MODE' as const;
export const BOTMUX_CAN_OPENMEMORY_ENV = 'BOTMUX_CAN_OPENMEMORY' as const;

/**
 * Attach the host-decided owner posture to one native CLI process. The raw
 * OpenMemory key remains in MemoryGate; the child receives only a short-lived,
 * session-bound capability. MCP configuration is process-scoped so BotMux does
 * not mutate the user's global Codex or Claude configuration.
 */
export function applyNativeOwnerRuntime(input: {
  readonly cliId: string;
  readonly executionMode?: 'native' | 'podman';
  readonly ownerCanOpenMemory?: boolean;
  readonly memoryGateCapability?: string;
  readonly args: string[];
  readonly env: NodeJS.ProcessEnv;
}): void {
  const native = input.executionMode === 'native';
  input.env[BOTMUX_EXECUTION_MODE_ENV] = native ? 'native' : 'podman';
  input.env[BOTMUX_CAN_OPENMEMORY_ENV] = native && input.ownerCanOpenMemory === true ? '1' : '0';

  if (!native || !input.memoryGateCapability) return;
  input.env[MEMORY_GATE_CAPABILITY_ENV] = input.memoryGateCapability;

  if (input.cliId === 'codex') {
    input.args.push(
      '-c', `mcp_servers.openmemory.url=${JSON.stringify(MEMORY_GATE_URL)}`,
      '-c', `mcp_servers.openmemory.bearer_token_env_var=${JSON.stringify(MEMORY_GATE_CAPABILITY_ENV)}`,
    );
    return;
  }
  if (input.cliId === 'claude-code') {
    input.args.push('--mcp-config', JSON.stringify({
      mcpServers: {
        openmemory: {
          type: 'http',
          url: MEMORY_GATE_URL,
          headers: { Authorization: `Bearer \${${MEMORY_GATE_CAPABILITY_ENV}}` },
        },
      },
    }));
  }
}
