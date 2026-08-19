/** Runtime bridge from a daemon session to the app-scoped principal authority. */
import { AgentPrincipalRepository, createAgentPrincipalPool } from '../services/agent-principal-store.js';
import { loadCredentialMasterKey } from '../services/agent-principal-crypto.js';
import { bindNewPodmanSession, materializeColdPodmanCredential } from './agent-principal-boundary.js';
import type { DaemonSession } from './types.js';
import { buildSessionRuntimePaths } from '../execution/podman-execution.js';
import type { PodmanExecutionConfig } from '../execution/podman-execution.js';
import { writeCodexAuthJson } from '../services/codex-device-login.js';
import { lstatSync, readFileSync } from 'node:fs';

let repository: AgentPrincipalRepository | undefined;

function getRepository(): AgentPrincipalRepository {
  if (repository) return repository;
  const pool = createAgentPrincipalPool();
  repository = new AgentPrincipalRepository(pool, loadCredentialMasterKey());
  return repository;
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
}): Promise<void> {
  const { ds, execution, cliId } = input;
  if (!execution) return;
  // The daemon clears credentialSecret immediately after dispatching init, so
  // its absence alone does not mean this topic is cold. A live worker already
  // owns the frozen binding and must never trigger a per-message DB lookup.
  if (ds.worker && !ds.worker.killed) return;
  if (!ds.session.execution) {
    ds.session.execution = execution;
    input.persist?.(ds.session);
  }
  if (ds.session.principalBinding && ds.session.credentialBinding) {
    if (!ds.credentialSecret) {
      const resolved = await materializeColdPodmanCredential({
        ds,
        cliId,
        repository: getRepository(),
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
    return;
  }
  const resolved = await bindNewPodmanSession({
    ds,
    cliId,
    repository: getRepository(),
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
  }
}

export function __testOnly_resetAgentPrincipalRuntime(): void {
  repository = undefined;
}
