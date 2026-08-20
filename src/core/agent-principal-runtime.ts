/** Runtime bridge from a daemon session to the app-scoped principal authority. */
import { AgentPrincipalRepository, applyAgentPrincipalMigration, createAgentPrincipalPool } from '../services/agent-principal-store.js';
import { applySandboxUserRegistryMigration, SandboxUserRegistryRepository } from '../services/sandbox-user-registry.js';
import type { FrozenPrincipalSkillBinding } from '../services/agent-principal-skills.js';
import { loadCredentialMasterKey } from '../services/agent-principal-crypto.js';
import { bindNewPodmanSession, materializeColdPodmanCredential } from './agent-principal-boundary.js';
import type { DaemonSession } from './types.js';
import { buildSessionRuntimePaths } from '../execution/podman-execution.js';
import type { PodmanExecutionConfig } from '../execution/podman-execution.js';
import { writeCodexAuthJson } from '../services/codex-device-login.js';
import { lstatSync, readFileSync } from 'node:fs';
import {
  buildOwnerMemoryGatePlan,
  loadMemoryGateCapabilitySecretFromConfig,
  probeMemoryGateReadiness,
  supportsOwnerMemoryMcp,
} from '../services/openmemory-memory-gate.js';
import { principalHash, sessionHash } from '../execution/podman-execution.js';

let repository: AgentPrincipalRepository | undefined;
let repositoryMigration: Promise<void> | undefined;
const MEMORY_GATE_STARTUP_ATTEMPTS = 6;
const MEMORY_GATE_STARTUP_RETRY_MS = 500;

function getRepository(): AgentPrincipalRepository {
  if (repository) return repository;
  const pool = createAgentPrincipalPool();
  const masterKey = loadCredentialMasterKey();
  repository = new AgentPrincipalRepository(pool, masterKey, new SandboxUserRegistryRepository(pool, masterKey));
  repositoryMigration = (async () => {
    // Both migrations are additive and run before the first new-topic lookup;
    // this prevents a production process from silently taking the V3 guest
    // fallback because the V4 tables have not been created yet.
    await applyAgentPrincipalMigration(pool);
    await applySandboxUserRegistryMigration(pool);
  })();
  return repository;
}

async function getRepositoryReady(): Promise<AgentPrincipalRepository> {
  const value = getRepository();
  await repositoryMigration;
  return value;
}

async function waitForMemoryGateReadiness(secret: string): Promise<boolean> {
  for (let attempt = 0; attempt < MEMORY_GATE_STARTUP_ATTEMPTS; attempt += 1) {
    if (await probeMemoryGateReadiness({ secret })) return true;
    if (attempt + 1 < MEMORY_GATE_STARTUP_ATTEMPTS) {
      await new Promise(resolve => setTimeout(resolve, MEMORY_GATE_STARTUP_RETRY_MS));
    }
  }
  return false;
}

function materializeCodexCredential(input: {
  readonly ds: DaemonSession;
  readonly execution: PodmanExecutionConfig;
  readonly credentialKind: string;
  readonly credentialSecret: string;
}): void {
  if (input.credentialKind !== 'codex_chatgpt') return;
  const binding = input.ds.session.principalBinding;
  const openId = binding?.openId ?? binding?.open_id ?? input.ds.ownerOpenId ?? input.ds.session.ownerOpenId;
  if (!openId || binding?.larkAppId !== input.ds.larkAppId) {
    throw new Error('cold sandbox principal identity is invalid');
  }
  const runtime = buildSessionRuntimePaths(
    input.execution,
    { larkAppId: input.ds.larkAppId, openId },
    input.ds.session.sessionId,
  );
  writeCodexAuthJson({ authPath: runtime.codexAuthPath, authJson: input.credentialSecret });
}

/** Synchronous invariant checked immediately before a Podman worker fork. */
export function assertPodmanPrincipalReadyForFork(input: {
  readonly ds: DaemonSession;
  readonly execution: PodmanExecutionConfig;
  readonly cliId: string;
}): void {
  const principal = input.ds.session.principalBinding;
  const credential = input.ds.session.credentialBinding;
  if (!principal || principal.enabled !== true || !credential) {
    throw new Error('Podman cold fork requires complete frozen principal bindings');
  }
  const kind = credential.kind ?? credential.credentialKind;
  if (kind === 'api') {
    if (typeof input.ds.credentialSecret !== 'string' || input.ds.credentialSecret.length === 0) {
      throw new Error('Podman API cold fork requires a transient credential secret');
    }
    return;
  }
  if (input.cliId !== 'codex' || kind !== 'codex_chatgpt') {
    throw new Error('Podman credential binding is incompatible with the fixed bot harness');
  }
  const openId = principal.openId ?? principal.open_id;
  if (!openId || principal.larkAppId !== input.ds.larkAppId) {
    throw new Error('Podman ChatGPT principal identity is invalid');
  }
  const authPath = buildSessionRuntimePaths(
    input.execution,
    { larkAppId: input.ds.larkAppId, openId },
    input.ds.session.sessionId,
  ).codexAuthPath;
  let stat: ReturnType<typeof lstatSync>;
  try { stat = lstatSync(authPath); } catch { throw new Error('Podman ChatGPT cold fork requires materialized auth'); }
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) {
    throw new Error('Podman ChatGPT auth material is not a private regular file');
  }
  try {
    const parsed = JSON.parse(readFileSync(authPath, 'utf8')) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
      || Object.keys(parsed as Record<string, unknown>).length === 0) throw new Error('empty auth');
  } catch {
    throw new Error('Podman ChatGPT cold fork requires valid auth material');
  }
}

async function prepareOwnerMemoryCapability(ds: DaemonSession, cliId: string): Promise<void> {
  const binding = ds.session.principalBinding;
  ds.memoryGateCapability = undefined;
  const nativeOwner = ds.session.executionMode === 'native'
    && ds.session.ownerCanOpenMemory === true;
  if (!nativeOwner && (!binding || binding.enabled !== true || binding.canOpenMemory !== true)) return;
  if (!supportsOwnerMemoryMcp(cliId)) {
    throw new Error('owner OpenMemory MCP is unsupported by this harness');
  }
  const openId = binding?.openId ?? binding?.open_id ?? ds.ownerOpenId ?? ds.session.ownerOpenId;
  if (!openId || (binding && binding.larkAppId !== ds.larkAppId)) {
    throw new Error('owner OpenMemory principal identity is invalid');
  }
  const secret = loadMemoryGateCapabilitySecretFromConfig();
  if (!secret) throw new Error('owner OpenMemory capability secret is not configured');
  if (!(await waitForMemoryGateReadiness(secret))) {
    throw new Error('owner OpenMemory gate is not ready');
  }
  const plan = buildOwnerMemoryGatePlan({
    principal: binding ?? { enabled: true, canOpenMemory: nativeOwner },
    cliId,
    sessionHash: sessionHash(ds.larkAppId, openId, ds.session.sessionId),
    principalHash: principalHash(ds.larkAppId, openId),
    capabilitySecret: secret,
  });
  if (!plan) throw new Error('owner OpenMemory capability could not be prepared');
  ds.memoryGateCapability = plan.capability;
}

/**
 * Resolve once for a new Podman topic, or rehydrate only a cold worker. The
 * returned secret lives only on DaemonSession until worker init; Session gets
 * non-secret frozen bindings through the boundary's persist callback.
 */
export async function ensureSandboxPrincipalForFork(input: {
  readonly ds: DaemonSession;
  readonly execution?: PodmanExecutionConfig;
  readonly cliId: string;
  readonly persist?: (session: DaemonSession['session']) => void;
  /** Test seam; production always uses the process-wide repository. */
  readonly repository?: Pick<AgentPrincipalRepository, 'resolveExecutionModeForNewInstance' | 'resolveForNewInstance'>;
}): Promise<void> {
  const { ds, execution, cliId } = input;
  // The daemon clears credentialSecret immediately after dispatching init, so
  // its absence alone does not mean this topic is cold. A live worker already
  // owns the frozen binding and must never trigger a per-message DB lookup.
  if (ds.worker && !ds.worker.killed) return;
  let principalRepository = input.repository;
  const readyRepository = async () => principalRepository ??= await getRepositoryReady();
  // Native is a durable per-session decision. Old native sessions predate the
  // frozen capability bit, so hydrate that non-secret posture once at a cold
  // fork. Ordinary topic messages with a live worker never query PostgreSQL.
  if (ds.session.executionMode === 'native') {
    if (ds.session.ownerCanOpenMemory === undefined) {
      const openId = ds.ownerOpenId ?? ds.session.ownerOpenId;
      if (!openId) throw new Error('a native owner session requires an app-scoped owner open_id');
      const mode = await (await readyRepository()).resolveExecutionModeForNewInstance({
        key: { larkAppId: ds.larkAppId, openId },
        ownerOpenId: openId,
      });
      if (mode.executionMode !== 'native') {
        throw new Error('frozen native session no longer resolves to a native principal');
      }
      ds.session.ownerCanOpenMemory = mode.principal.canOpenMemory === true;
      if ((mode.principalSkills?.length ?? 0) > 0) {
        ds.session.principalSkills = [...mode.principalSkills] as FrozenPrincipalSkillBinding[];
      }
      input.persist?.(ds.session);
    }
    await prepareOwnerMemoryCapability(ds, cliId);
    return;
  }
  if (!execution) return;
  const resolvedRepository = await readyRepository();
  // Some creation paths pre-seed Session.execution from the live bot config
  // before this async boundary runs. That value is only a candidate profile,
  // not a frozen decision; the mode/binding fields are the authoritative
  // new-instance marker.
  if (!ds.session.executionMode && !ds.session.principalBinding && !ds.session.credentialBinding) {
    const openId = ds.ownerOpenId ?? ds.session.ownerOpenId;
    if (!openId) throw new Error('a sandbox session requires an app-scoped owner open_id');
    const mode = await resolvedRepository.resolveExecutionModeForNewInstance({
      key: { larkAppId: ds.larkAppId, openId },
      ownerOpenId: openId,
    });
    ds.session.executionMode = mode.executionMode;
    ds.session.ownerCanOpenMemory = mode.executionMode === 'native'
      ? mode.principal.canOpenMemory === true
      : undefined;
    if (mode.sandboxUserId !== undefined || mode.podGeneration !== undefined) {
      if (mode.sandboxUserId === undefined || mode.podGeneration === undefined) {
        throw new Error('stable sandbox pod binding is incomplete');
      }
      ds.session.sandboxUserId = mode.sandboxUserId;
      ds.session.podGeneration = mode.podGeneration;
    }
    if (mode.principalSkills && mode.principalSkills.length > 0) {
      ds.session.principalSkills = [...mode.principalSkills] as FrozenPrincipalSkillBinding[];
    }
    if (mode.executionMode === 'native') {
      // Remove a pre-seeded Podman profile before persisting the native freeze;
      // forkWorker must not be able to recover it on a cold restart.
      ds.session.execution = undefined;
    }
    input.persist?.(ds.session);
    if (mode.executionMode === 'native') {
      await prepareOwnerMemoryCapability(ds, cliId);
      return;
    }
  } else if (!ds.session.executionMode) {
    // Sessions persisted by the pre-mode build are already Podman-bound when
    // they carry execution/principal material. Preserve that conservative
    // posture and make the decision explicit for future cold restarts.
    ds.session.executionMode = 'podman';
    input.persist?.(ds.session);
  }
  if (!ds.session.execution) {
    ds.session.execution = execution;
    input.persist?.(ds.session);
  }
  if (ds.session.principalBinding && ds.session.credentialBinding) {
    if (!ds.credentialSecret) {
      const resolved = await materializeColdPodmanCredential({
        ds,
        cliId,
        repository: resolvedRepository,
        persist: input.persist ? session => input.persist?.(session) : undefined,
      });
      materializeCodexCredential({
        ds,
        execution,
        credentialKind: resolved.credentialBinding.kind,
        credentialSecret: resolved.credentialSecret,
      });
      ds.credentialSecret = resolved.credentialBinding.kind === 'api'
        ? resolved.credentialSecret
        : undefined;
    } else {
      const credentialKind = ds.session.credentialBinding.kind ?? ds.session.credentialBinding.credentialKind ?? '';
      if (credentialKind === 'codex_chatgpt') {
        materializeCodexCredential({ ds, execution, credentialKind, credentialSecret: ds.credentialSecret });
        ds.credentialSecret = undefined;
      }
    }
    try {
      await prepareOwnerMemoryCapability(ds, cliId);
    } catch (error) {
      ds.credentialSecret = undefined;
      ds.memoryGateCapability = undefined;
      throw error;
    }
    return;
  }
  const resolved = await bindNewPodmanSession({
    ds,
    cliId,
    repository: resolvedRepository,
    persist: session => input.persist?.(session),
  });
  if (resolved) {
    materializeCodexCredential({
      ds,
      execution,
      credentialKind: resolved.credentialBinding.kind,
      credentialSecret: resolved.credentialSecret,
    });
    ds.credentialSecret = resolved.credentialBinding.kind === 'api'
      ? resolved.credentialSecret
      : undefined;
    try {
      await prepareOwnerMemoryCapability(ds, cliId);
    } catch (error) {
      ds.credentialSecret = undefined;
      ds.memoryGateCapability = undefined;
      throw error;
    }
  }
}

export function __testOnly_resetAgentPrincipalRuntime(): void {
  repository = undefined;
  repositoryMigration = undefined;
}
