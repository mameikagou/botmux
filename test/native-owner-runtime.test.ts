import { describe, expect, it } from 'vitest';
import {
  applyNativeOwnerRuntime,
  BOTMUX_CAN_OPENMEMORY_ENV,
  BOTMUX_EXECUTION_MODE_ENV,
} from '../src/core/native-owner-runtime.js';
import { MEMORY_GATE_CAPABILITY_ENV, MEMORY_GATE_URL } from '../src/services/openmemory-memory-gate.js';

describe('native owner runtime', () => {
  it('injects a native Codex MCP config without putting the capability in argv', () => {
    const capability = 'v1.secret-session-bound-capability';
    const args = ['--no-alt-screen'];
    const env: NodeJS.ProcessEnv = {};
    applyNativeOwnerRuntime({
      cliId: 'codex',
      executionMode: 'native',
      ownerCanOpenMemory: true,
      memoryGateCapability: capability,
      args,
      env,
    });

    expect(env).toMatchObject({
      [BOTMUX_EXECUTION_MODE_ENV]: 'native',
      [BOTMUX_CAN_OPENMEMORY_ENV]: '1',
      [MEMORY_GATE_CAPABILITY_ENV]: capability,
    });
    expect(args.join(' ')).toContain(MEMORY_GATE_URL);
    expect(args.join(' ')).toContain(MEMORY_GATE_CAPABILITY_ENV);
    expect(args.join(' ')).not.toContain(capability);
  });

  it('uses Claude environment expansion and keeps guests capability-free', () => {
    const capability = 'session-capability';
    const nativeArgs: string[] = [];
    const nativeEnv: NodeJS.ProcessEnv = {};
    applyNativeOwnerRuntime({
      cliId: 'claude-code', executionMode: 'native', ownerCanOpenMemory: true,
      memoryGateCapability: capability, args: nativeArgs, env: nativeEnv,
    });
    expect(nativeArgs).toContain('--mcp-config');
    expect(nativeArgs.join(' ')).toContain(`\${${MEMORY_GATE_CAPABILITY_ENV}}`);
    expect(nativeArgs.join(' ')).not.toContain(capability);

    const guestArgs: string[] = [];
    const guestEnv: NodeJS.ProcessEnv = {};
    applyNativeOwnerRuntime({
      cliId: 'codex', executionMode: 'podman', ownerCanOpenMemory: false,
      memoryGateCapability: capability, args: guestArgs, env: guestEnv,
    });
    expect(guestEnv).toEqual({
      [BOTMUX_EXECUTION_MODE_ENV]: 'podman',
      [BOTMUX_CAN_OPENMEMORY_ENV]: '0',
    });
    expect(guestArgs).toEqual([]);
  });
});
