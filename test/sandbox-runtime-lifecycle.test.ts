import { describe, expect, it } from 'vitest';
import {
  beginSandboxRuntimeLifecycle,
  runtimeIdForSession,
} from '../src/services/sandbox-runtime-lifecycle.js';
import type {
  SandboxPodRuntimeManifest,
  SandboxRuntimeState,
} from '../src/services/sandbox-user-registry.js';
import type { PodmanExecutionConfig } from '../src/execution/podman-execution.js';

const execution: PodmanExecutionConfig = {
  type: 'podman',
  image: 'localhost/botmux-quant-dev@sha256:' + 'a'.repeat(64),
  sourceRepo: '/workspace/analyze',
  sourceBranch: 'main',
  runtimeRoot: '/var/tmp/botmux-runtime',
  credentialCacheRoot: '/var/tmp/botmux-credentials',
  dataRoot: '/workspace/analyze/qlib/data',
  knowledgeRoot: '/workspace/analyze/knowledge/investment-books',
  ownerMemoryGate: '127.0.0.1:18181',
  idleTimeoutMinutes: 30,
  memory: '4g',
  cpus: 2,
};

class RuntimeRepository {
  manifest?: SandboxPodRuntimeManifest;
  readonly transitions: Array<{ state: SandboxRuntimeState; expectedState?: SandboxRuntimeState; failureCode?: string }> = [];

  async createRuntime(input: Omit<SandboxPodRuntimeManifest, 'state' | 'createdAt' | 'updatedAt'> & { runtimeId: string }): Promise<SandboxPodRuntimeManifest> {
    const now = new Date().toISOString();
    this.manifest = {
      ...input,
      state: 'provisioning',
      createdAt: now,
      updatedAt: now,
    };
    return this.manifest;
  }

  async getRuntime(runtimeId: string): Promise<SandboxPodRuntimeManifest | undefined> {
    return this.manifest?.runtimeId === runtimeId ? this.manifest : undefined;
  }

  async getRuntimeForSession(input: { sessionId: string; podGeneration: number }): Promise<SandboxPodRuntimeManifest | undefined> {
    return this.manifest?.sessionId === input.sessionId && this.manifest.podGeneration === input.podGeneration
      ? this.manifest : undefined;
  }

  async updateRuntimeState(input: {
    runtimeId: string;
    state: SandboxRuntimeState;
    expectedState?: SandboxRuntimeState;
    failureCode?: string;
  }): Promise<SandboxPodRuntimeManifest> {
    if (!this.manifest || this.manifest.runtimeId !== input.runtimeId) throw new Error('missing');
    if (input.expectedState !== undefined && this.manifest.state !== input.expectedState) {
      const error = new Error('sandbox_runtime_state_conflict') as Error & { runtimeId: string; expectedState: SandboxRuntimeState; actualState: SandboxRuntimeState };
      error.name = 'SandboxRuntimeStateConflictError';
      error.runtimeId = input.runtimeId;
      error.expectedState = input.expectedState;
      error.actualState = this.manifest.state;
      throw error;
    }
    this.transitions.push({ state: input.state, expectedState: input.expectedState, failureCode: input.failureCode });
    this.manifest = {
      ...this.manifest,
      state: input.state,
      updatedAt: new Date().toISOString(),
      ...(input.failureCode === undefined ? {} : { failureCode: input.failureCode }),
    };
    return this.manifest;
  }
}

function input(sessionId = 'session-a') {
  return {
    sessionId,
    sandboxUserId: 'guest-a',
    podGeneration: 1,
    execution,
    larkAppId: 'cli_guest',
    openId: 'ou_guest',
    harness: 'claude-code',
    credentialVersion: 4,
  } as const;
}

describe('sandbox runtime lifecycle', () => {
  it('creates one stable provisioning manifest, then performs CAS lifecycle transitions', async () => {
    const repository = new RuntimeRepository();
    const first = await beginSandboxRuntimeLifecycle(repository, input());
    expect(first?.runtimeId).toBe(runtimeIdForSession('session-a', 'guest-a', 1));
    expect(first?.manifest.state).toBe('provisioning');
    expect(first?.manifest.sandboxUserId).toBe('guest-a');
    expect(first?.manifest.credentialVersion).toBe(4);
    expect(first?.manifest).not.toHaveProperty('secret');

    await first!.markRunning();
    await first!.markStopping();
    await first!.markStopped();
    expect(repository.transitions.map(item => item.state)).toEqual(['running', 'stopping', 'stopped']);

    const cold = await beginSandboxRuntimeLifecycle(repository, input());
    expect(cold?.runtimeId).toBe(first?.runtimeId);
    expect(cold?.manifest.state).toBe('provisioning');
    expect(repository.transitions.at(-1)?.state).toBe('provisioning');
  });

  it('does nothing for native/pre-v4 sessions, and fails closed on a mismatched manifest', async () => {
    const repository = new RuntimeRepository();
    expect(await beginSandboxRuntimeLifecycle(repository, { ...input(), sandboxUserId: undefined })).toBeUndefined();
    await beginSandboxRuntimeLifecycle(repository, input());
    await expect(beginSandboxRuntimeLifecycle(repository, { ...input(), harness: 'codex' }))
      .rejects.toThrow('sandbox runtime manifest does not match');
  });

  it('records a failure with a sanitized operational code', async () => {
    const repository = new RuntimeRepository();
    const handle = await beginSandboxRuntimeLifecycle(repository, input('failed-session'));
    await handle!.markFailed('podman_prepare_failed');
    expect(repository.manifest?.state).toBe('failed');
    expect(repository.manifest?.failureCode).toBe('podman_prepare_failed');
  });
});
