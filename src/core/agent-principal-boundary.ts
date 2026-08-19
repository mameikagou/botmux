/**
 * Session boundary for shared-sandbox principal and BYOK resolution.
 *
 * This module intentionally has no message polling hook. A new-topic caller
 * invokes bindNewPodmanSession once before the first worker; an existing topic
 * reuses the frozen Session fields. A cold worker recreation may call the same
 * function only when the non-secret binding is absent.
 */
import type { Session } from '../types.js';
import type { PodmanExecutionConfig, PodmanCliId } from '../execution/podman-execution.js';
import {
  AgentPrincipalLookupError,
  type AgentPrincipalKey,
  type AgentPrincipalRepository,
  type FrozenCredentialBinding,
  type FrozenPrincipalBinding,
} from '../services/agent-principal-store.js';
import type { DaemonSession } from './types.js';

export interface PrincipalBoundaryResult {
  readonly principalBinding: FrozenPrincipalBinding;
  readonly credentialBinding: FrozenCredentialBinding;
  /** Deliberately returned only to the caller and never written to Session. */
  readonly credentialSecret: string;
}

export type PrincipalBoundaryLookup = Pick<AgentPrincipalRepository, 'resolveForNewInstance'>;

export function podmanSessionExecution(session: Pick<Session, 'execution'>): PodmanExecutionConfig | undefined {
  return session.execution;
}

export function hasFrozenPrincipalBinding(session: Pick<Session, 'execution' | 'principalBinding' | 'credentialBinding'>): boolean {
  if (!session.execution) return true;
  return !!session.principalBinding && !!session.credentialBinding;
}

/**
 * Resolve a principal exactly at the instance boundary. The `persist` callback
 * must write only the two non-secret bindings to Session. The caller keeps the
 * returned secret in an in-memory DaemonSession field until init is sent.
 */
export async function bindNewPodmanSession(input: {
  readonly ds: Pick<DaemonSession, 'session' | 'larkAppId' | 'ownerOpenId'>;
  readonly cliId: string;
  readonly repository: PrincipalBoundaryLookup;
  readonly persist: (session: Session) => void;
  readonly adminOverride?: boolean;
}): Promise<PrincipalBoundaryResult | undefined> {
  if (!input.ds.session.execution) return undefined;
  if (input.ds.session.principalBinding || input.ds.session.credentialBinding) {
    if (!input.ds.session.principalBinding || !input.ds.session.credentialBinding) {
      throw new AgentPrincipalLookupError('credential_missing', 'partial frozen principal binding is not valid');
    }
    // A durable binding is the only authority for an existing topic. It is
    // intentionally not re-read on every ordinary message. The secret cannot
    // be reconstructed from Session, so a caller without cold-start material
    // must explicitly perform the cold lookup below.
    return undefined;
  }
  const openId = input.ds.ownerOpenId ?? input.ds.session.ownerOpenId;
  if (!openId) throw new AgentPrincipalLookupError('not_found', 'a sandbox session requires an app-scoped owner open_id');
  const resolved = await input.repository.resolveForNewInstance({
    key: { larkAppId: input.ds.larkAppId, openId },
    cliId: input.cliId,
    ownerOpenId: openId,
    adminOverride: input.adminOverride,
  });
  input.ds.session.principalBinding = resolved.principalBinding;
  input.ds.session.credentialBinding = resolved.credentialBinding;
  input.ds.session.cliId = input.cliId as PodmanCliId;
  input.persist(input.ds.session);
  return {
    principalBinding: resolved.principalBinding,
    credentialBinding: resolved.credentialBinding,
    credentialSecret: resolved.credentialSecret,
  };
}

/**
 * Rehydrate the transient secret for a stopped/cold session. A live topic does
 * not call this method merely because another message arrived; the daemon calls
 * it only from its worker recreation path.
 */
export async function materializeColdPodmanCredential(input: {
  readonly ds: Pick<DaemonSession, 'session' | 'larkAppId' | 'ownerOpenId'>;
  readonly cliId: string;
  readonly repository: PrincipalBoundaryLookup;
  /** Persist refreshed non-secret metadata after an accepted rotation. */
  readonly persist?: (session: Session) => void;
}): Promise<PrincipalBoundaryResult> {
  if (!input.ds.session.execution || !input.ds.session.principalBinding || !input.ds.session.credentialBinding) {
    throw new AgentPrincipalLookupError('credential_missing', 'cold sandbox session has no complete frozen principal binding');
  }
  const binding = input.ds.session.principalBinding;
  const openId = binding.openId ?? binding.open_id ?? input.ds.ownerOpenId ?? input.ds.session.ownerOpenId;
  if (!openId || binding.larkAppId !== input.ds.larkAppId) {
    throw new AgentPrincipalLookupError('not_found', 'cold session principal app-scoped identity is invalid');
  }
  const resolved = await input.repository.resolveForNewInstance({
    key: { larkAppId: input.ds.larkAppId, openId },
    cliId: input.cliId,
    ownerOpenId: openId,
  });
  // A cold worker is a new process boundary. Rotation is therefore allowed to
  // refresh the non-secret frozen metadata here, while disable/delete still
  // fail closed in resolveForNewInstance above. A credential-kind change is a
  // different injection contract and cannot be silently re-bound.
  if (resolved.credentialBinding.kind !== input.ds.session.credentialBinding.kind) {
    throw new AgentPrincipalLookupError('credential_incompatible', 'stored credential version no longer matches the frozen session');
  }
  const frozenPrincipal = input.ds.session.principalBinding;
  const frozenCredential = input.ds.session.credentialBinding;
  const sessionOwnerOpenId = input.ds.ownerOpenId ?? input.ds.session.ownerOpenId;
  if (frozenPrincipal.enabled !== true
    || (frozenPrincipal.openId ?? frozenPrincipal.open_id) !== openId
    || (frozenPrincipal.ownerOpenId !== undefined
      && frozenPrincipal.ownerOpenId !== sessionOwnerOpenId)
    || frozenPrincipal.cliId !== undefined && frozenPrincipal.cliId !== input.cliId
    || frozenPrincipal.credentialVersion !== undefined
      && frozenPrincipal.credentialVersion !== frozenCredential.credentialVersion
    || frozenPrincipal.credentialKind !== undefined
      && frozenPrincipal.credentialKind !== frozenCredential.kind) {
    throw new AgentPrincipalLookupError('credential_incompatible', 'cold session principal binding failed integrity checks');
  }
  const frozenVersion = frozenCredential.credentialVersion;
  const frozenKind = frozenCredential.kind;
  if (typeof frozenVersion !== 'number' || !Number.isInteger(frozenVersion) || frozenVersion < 1
    || (frozenKind !== 'codex_chatgpt' && frozenKind !== 'api')) {
    throw new AgentPrincipalLookupError('credential_incompatible', 'cold session credential binding is incomplete');
  }
  const refreshedPrincipal = {
    ...resolved.principalBinding,
    // Keep the session's original owner binding. The repository already
    // checked that ownerOpenId is authorized for this cold lookup.
    ...(frozenPrincipal.ownerOpenId ? { ownerOpenId: frozenPrincipal.ownerOpenId } : {}),
  };
  const refreshedCredential = resolved.credentialBinding;
  input.ds.session.principalBinding = refreshedPrincipal;
  input.ds.session.credentialBinding = refreshedCredential;
  input.persist?.(input.ds.session);
  return {
    principalBinding: refreshedPrincipal,
    credentialBinding: refreshedCredential,
    credentialSecret: resolved.credentialSecret,
  };
}

/** A routing helper used by tests and ingress callers to document the DB rule. */
export function shouldLookupPrincipalAtIngress(input: {
  readonly isDirectBotMessage: boolean;
  readonly createsNewInstance: boolean;
  readonly existingSessionHasFrozenBinding: boolean;
  readonly coldWorkerRebuild: boolean;
}): boolean {
  if (input.coldWorkerRebuild) return true;
  if (input.existingSessionHasFrozenBinding) return false;
  return input.isDirectBotMessage && input.createsNewInstance;
}
