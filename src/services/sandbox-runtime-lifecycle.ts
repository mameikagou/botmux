/**
 * Durable lifecycle fence for a V4 guest session.
 *
 * The daemon freezes the user/pod/credential binding on Session. This service
 * is deliberately called only at worker provisioning and teardown boundaries;
 * it must never be used from an ordinary topic-message route. The manifest is
 * non-secret and is retained after a Pod/container disappears so a later
 * worker can cold-start from an authoritative record.
 */
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import {
  buildSessionRuntimePaths,
  type PodmanExecutionConfig,
} from '../execution/podman-execution.js';
import {
  SandboxRuntimeStateConflictError,
  SandboxUserLookupError,
  type SandboxPodRuntimeManifest,
  type SandboxRuntimeState,
  type SandboxUserRegistryRepository,
  type SandboxUserHarness,
} from './sandbox-user-registry.js';

export interface SandboxRuntimeLifecycleInput {
  readonly sessionId: string;
  readonly sandboxUserId?: string;
  readonly podGeneration?: number;
  readonly execution?: PodmanExecutionConfig;
  readonly larkAppId: string;
  readonly openId?: string;
  readonly harness: string;
  readonly credentialVersion?: number;
}

export interface SandboxRuntimeLifecycleHandle {
  readonly runtimeId: string;
  readonly manifest: SandboxPodRuntimeManifest;
  markRunning(): Promise<SandboxPodRuntimeManifest>;
  markStopping(): Promise<SandboxPodRuntimeManifest | undefined>;
  markStopped(): Promise<SandboxPodRuntimeManifest | undefined>;
  markFailed(failureCode: string): Promise<SandboxPodRuntimeManifest | undefined>;
}

type RuntimeRepository = Pick<
  SandboxUserRegistryRepository,
  'createRuntime' | 'getRuntime' | 'getRuntimeForSession' | 'updateRuntimeState'
>;

const HARNESS_VALUES = new Set<SandboxUserHarness>(['codex', 'claude-code', 'pi', 'opencode']);

function nonEmpty(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.trim() === '' || /[\u0000\r\n]/u.test(value)) {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value.trim();
}

function runtimeIdForSession(sessionId: string, sandboxUserId = 'legacy', podGeneration = 1): string {
  const digest = createHash('sha256')
    .update(`${sandboxUserId}:${String(podGeneration)}:${sessionId}`)
    .digest('hex')
    .slice(0, 48);
  return `sandbox-runtime-${digest}`;
}

function harnessFor(raw: string): SandboxUserHarness {
  if (!HARNESS_VALUES.has(raw as SandboxUserHarness)) throw new TypeError('invalid sandbox harness');
  return raw as SandboxUserHarness;
}

function isExpectedStateConflict(error: unknown): error is SandboxRuntimeStateConflictError {
  return error instanceof SandboxRuntimeStateConflictError;
}

/**
 * A no-op for native sessions and pre-V4 rows. For a V4 guest it writes (or
 * reopens) the one manifest keyed by Session id and returns a small lifecycle
 * handle. Database failures intentionally escape: a new guest must not launch
 * without a durable recovery record.
 */
export async function beginSandboxRuntimeLifecycle(
  repository: RuntimeRepository,
  input: SandboxRuntimeLifecycleInput,
): Promise<SandboxRuntimeLifecycleHandle | undefined> {
  if (input.sandboxUserId === undefined || input.podGeneration === undefined || input.execution === undefined) {
    return undefined;
  }
  const sessionId = nonEmpty(input.sessionId, 'sessionId');
  const sandboxUserId = nonEmpty(input.sandboxUserId, 'sandboxUserId');
  if (!Number.isSafeInteger(input.podGeneration) || input.podGeneration < 1) {
    throw new TypeError('podGeneration must be a positive integer');
  }
  const podGeneration = input.podGeneration;
  const harness = harnessFor(nonEmpty(input.harness, 'harness'));
  const execution = input.execution;
  const openId = input.openId ? nonEmpty(input.openId, 'openId') : undefined;
  // Use the provider's canonical path plan so the durable record points at
  // exactly the home/workspace/container that the later Podman launch binds.
  // The app/open pair is frozen in principalBinding for every guest session;
  // stable user id is only a defensive fallback for an old cold row.
  const runtime = buildSessionRuntimePaths(
    execution,
    { larkAppId: nonEmpty(input.larkAppId, 'larkAppId'), openId: openId ?? sandboxUserId },
    sessionId,
  );
  const manifestInput = {
    sandboxUserId,
    sessionId,
    harness,
    imageDigest: nonEmpty(execution.image, 'execution.image'),
    podGeneration,
    runtimeId: runtimeIdForSession(sessionId, sandboxUserId, input.podGeneration),
    containerName: runtime.containerName,
    workspacePath: join(runtime.workspaceRoot, 'analyze'),
    homePath: runtime.homeRoot,
    ...(input.credentialVersion !== undefined ? { credentialVersion: input.credentialVersion } : {}),
    sourceRepo: nonEmpty(execution.sourceRepo, 'execution.sourceRepo'),
    sourceBranch: nonEmpty(execution.sourceBranch, 'execution.sourceBranch'),
  } as const;

  let manifest = await repository.getRuntime(manifestInput.runtimeId);
  // A rolling V4 upgrade may have created the same session with a random
  // runtime id before deterministic ids were introduced. Reuse that row by
  // its immutable (session, generation) key rather than creating a duplicate.
  manifest ??= await repository.getRuntimeForSession({ sessionId, podGeneration });
  if (!manifest) {
    manifest = await repository.createRuntime(manifestInput);
  } else {
    assertManifestMatches(manifest, manifestInput);
    if (manifest.state !== 'provisioning') {
      manifest = await transition(repository, manifest, 'provisioning', [
        'running', 'stopping', 'stopped', 'failed',
      ]);
    }
  }

  return new LifecycleHandle(repository, manifest);
}

function assertManifestMatches(
  manifest: SandboxPodRuntimeManifest,
  expected: Pick<SandboxPodRuntimeManifest, 'sandboxUserId' | 'sessionId' | 'podGeneration' | 'harness' | 'imageDigest' | 'containerName' | 'workspacePath' | 'homePath' | 'credentialVersion' | 'sourceRepo' | 'sourceBranch'>,
): void {
  if (manifest.sandboxUserId !== expected.sandboxUserId
    || manifest.sessionId !== expected.sessionId
    || manifest.podGeneration !== expected.podGeneration
    || manifest.harness !== expected.harness
    || manifest.imageDigest !== expected.imageDigest
    || manifest.containerName !== expected.containerName
    || manifest.workspacePath !== expected.workspacePath
    || manifest.homePath !== expected.homePath
    || manifest.credentialVersion !== expected.credentialVersion
    || manifest.sourceRepo !== expected.sourceRepo
    || manifest.sourceBranch !== expected.sourceBranch) {
    throw new SandboxUserLookupError('runtime_conflict', 'sandbox runtime manifest does not match the frozen session');
  }
}

async function transition(
  repository: RuntimeRepository,
  current: SandboxPodRuntimeManifest,
  desired: SandboxRuntimeState,
  allowed: readonly SandboxRuntimeState[],
  failureCode?: string,
): Promise<SandboxPodRuntimeManifest> {
  if (current.state === desired) return current;
  if (!allowed.includes(current.state)) return current;
  try {
    return await repository.updateRuntimeState({
      runtimeId: current.runtimeId,
      state: desired,
      expectedState: current.state,
      ...(failureCode !== undefined ? { failureCode } : {}),
    });
  } catch (error) {
    // A concurrent worker/teardown may have won the CAS. Re-read once and
    // accept the already-advanced state; a second conflict is surfaced.
    if (!isExpectedStateConflict(error)) throw error;
    const latest = await repository.getRuntime(current.runtimeId);
    if (!latest) throw error;
    if (latest.state === desired || !allowed.includes(latest.state)) return latest;
    return repository.updateRuntimeState({
      runtimeId: latest.runtimeId,
      state: desired,
      expectedState: latest.state,
      ...(failureCode !== undefined ? { failureCode } : {}),
    });
  }
}

class LifecycleHandle implements SandboxRuntimeLifecycleHandle {
  constructor(
    private readonly repository: RuntimeRepository,
    private current: SandboxPodRuntimeManifest,
  ) {}

  get runtimeId(): string { return this.current.runtimeId; }
  get manifest(): SandboxPodRuntimeManifest { return this.current; }

  async markRunning(): Promise<SandboxPodRuntimeManifest> {
    this.current = await transition(this.repository, this.current, 'running', ['provisioning']);
    if (this.current.state !== 'running') {
      throw new SandboxUserLookupError('runtime_conflict', 'sandbox runtime did not reach running state');
    }
    return this.current;
  }

  async markStopping(): Promise<SandboxPodRuntimeManifest | undefined> {
    this.current = await transition(this.repository, this.current, 'stopping', ['provisioning', 'running']);
    return this.current;
  }

  async markStopped(): Promise<SandboxPodRuntimeManifest | undefined> {
    this.current = await transition(this.repository, this.current, 'stopped', ['provisioning', 'running', 'stopping']);
    return this.current;
  }

  async markFailed(failureCode: string): Promise<SandboxPodRuntimeManifest | undefined> {
    const code = nonEmpty(failureCode, 'failureCode');
    this.current = await transition(this.repository, this.current, 'failed', ['provisioning', 'running', 'stopping'], code);
    return this.current;
  }
}

export { runtimeIdForSession };
