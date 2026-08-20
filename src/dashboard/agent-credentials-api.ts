/** Minimal dashboard/pairing identity chain for per-principal BYOK. */
import type { AgentExecutionMode, AgentPrincipalKey, AgentPrincipalRepository, AgentCredentialMetadata, AgentPrincipalRow } from '../services/agent-principal-store.js';
import { AgentPrincipalLookupError, CodexLoginTaskConflictError } from '../services/agent-principal-store.js';
import { validateApiCredentialEndpoint, validateApiCredentialInput } from '../services/agent-credential-policy.js';
import { AgentCredentialProbeError } from '../services/agent-credential-probe.js';
import type { CodexDeviceLoginService, CodexLoginTaskView } from '../services/codex-device-login.js';

export interface AgentCredentialsApiRequest {
  readonly method: 'GET' | 'PUT' | 'PATCH' | 'DELETE' | 'POST';
  readonly path: string;
  readonly body?: unknown;
  /** Set by the already-authenticated dashboard/pairing request. */
  readonly principal: AgentPrincipalKey;
  /** Configured owner identity; execution-mode mutation is owner-only. */
  readonly ownerOpenId?: string;
  readonly chatType?: 'p2p' | 'group';
  readonly botCliId?: string;
}

export interface AgentCredentialsApiResponse {
  readonly status: number;
  readonly body: Record<string, unknown>;
}

export interface AgentCredentialsApiDeps {
  readonly repository: Pick<AgentPrincipalRepository,
    'getPrincipal' | 'getCredential' | 'putCredential' | 'deleteCredential' | 'setExecutionMode'>;
  readonly stopSessionsForPrincipal?: (key: AgentPrincipalKey) => Promise<void> | void;
  readonly loginService?: Pick<CodexDeviceLoginService, 'begin' | 'complete' | 'status' | 'logout'>;
  readonly validateEndpoint?: (baseUrl: string) => Promise<URL>;
  /** Required for API credential writes; tests may inject a deterministic seam. */
  readonly probeApiCredential?: (input: {
    readonly cliId: string;
    readonly apiKey: string;
    readonly baseUrl: string;
    readonly model: string;
  }) => Promise<void>;
}

function bodyObject(raw: unknown): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('request body must be an object');
  return raw as Record<string, unknown>;
}

function positiveVersion(raw: unknown): number | undefined {
  if (raw === undefined || raw === null || raw === '') return undefined;
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw < 0) throw new TypeError('expectedVersion must be a non-negative integer');
  return raw;
}

function publicCredential(credential: AgentCredentialMetadata | null | undefined): Record<string, unknown> | null {
  if (!credential) return null;
  return {
    credentialKind: credential.credentialKind,
    ...(credential.baseUrl ? { baseUrl: credential.baseUrl } : {}),
    ...(credential.model ? { model: credential.model } : {}),
    credentialVersion: credential.credentialVersion,
    updatedAt: credential.updatedAt,
    ...(credential.keyFingerprint ? { keyFingerprint: credential.keyFingerprint } : {}),
  };
}

function maskIdentity(value: string): string {
  if (value.length <= 4) return '*'.repeat(value.length);
  return `${value.slice(0, 2)}…${value.slice(-2)}`;
}

function publicPrincipal(principal: AgentPrincipalRow | undefined, botCliId?: string): Record<string, unknown> | null {
  if (!principal) return null;
  return {
    // The pairing session already fixes this identity. Show only a masked
    // confirmation; never render a complete open_id or app id in the page.
    larkAppId: maskIdentity(principal.larkAppId),
    openId: maskIdentity(principal.openId),
    ...(botCliId ? { harness: botCliId } : {}),
    enabled: principal.enabled,
    canOpenMemory: principal.canOpenMemory,
    executionMode: principal.executionMode,
    updatedAt: principal.updatedAt,
  };
}

function ok(body: Record<string, unknown>): AgentCredentialsApiResponse { return { status: 200, body: { ok: true, ...body } }; }
function bad(status: number, error: string): AgentCredentialsApiResponse { return { status, body: { ok: false, error } }; }

async function requireActivePrincipal(
  key: AgentPrincipalKey,
  repository: Pick<AgentPrincipalRepository, 'getPrincipal'>,
): Promise<AgentCredentialsApiResponse | undefined> {
  const principal = await repository.getPrincipal(key);
  if (!principal) return bad(404, 'principal_not_found');
  if (!principal.enabled) return bad(403, 'principal_disabled');
  return undefined;
}

function mapError(error: unknown): AgentCredentialsApiResponse {
  if (error instanceof AgentCredentialProbeError) return bad(502, 'credential_probe_failed');
  if (error instanceof CodexLoginTaskConflictError) return bad(409, 'codex_login_task_active');
  if (error instanceof AgentPrincipalLookupError) {
    if (error.code === 'not_found') return bad(404, 'principal_not_found');
    if (error.code === 'disabled') return bad(403, 'principal_disabled');
    if (error.code === 'database_unavailable') return bad(503, 'principal_database_unavailable');
    return bad(409, error.code);
  }
  if (error && typeof error === 'object' && (error as { name?: unknown }).name === 'CredentialVersionConflictError') {
    return bad(409, 'credential_version_conflict');
  }
  if (error instanceof TypeError) return bad(400, 'invalid_request');
  return bad(500, 'credential_operation_failed');
}

/**
 * Handle the small credential surface after dashboard/pairing authentication.
 * The caller supplies the app-scoped principal; no request body can select a
 * different `(larkAppId, open_id)`, and no secret is ever returned.
 */
export async function handleAgentCredentialsApi(
  request: AgentCredentialsApiRequest,
  deps: AgentCredentialsApiDeps,
): Promise<AgentCredentialsApiResponse> {
  const key = request.principal;
  try {
    if (request.path === '/api/agent/principal') {
      const principalError = await requireActivePrincipal(key, deps.repository);
      if (principalError) return principalError;
      if (request.method === 'PATCH') {
        // Host-native execution is a capability grant. A guest must never be
        // able to turn its own pairing into a host process, even though the
        // request is authenticated for that guest principal.
        if (!request.ownerOpenId || request.ownerOpenId !== key.openId) return bad(403, 'principal_owner_required');
        const body = bodyObject(request.body);
        if (body.executionMode !== 'native' && body.executionMode !== 'podman') throw new TypeError('executionMode is required');
        const updated = await deps.repository.setExecutionMode(key, body.executionMode as AgentExecutionMode);
        await deps.stopSessionsForPrincipal?.(key);
        return ok({ principal: publicPrincipal(updated, request.botCliId) });
      }
      if (request.method !== 'GET') return bad(403, 'principal_mutation_forbidden');
      return ok({ principal: publicPrincipal(await deps.repository.getPrincipal(key), request.botCliId) });
    }

    if (request.path === '/api/agent/model-credential') {
      const principalError = await requireActivePrincipal(key, deps.repository);
      if (principalError) return principalError;
      if (request.method === 'GET') return ok({ credential: publicCredential(await deps.repository.getCredential(key)) });
      if (request.method === 'DELETE') {
        const expectedVersion = positiveVersion(bodyObject(request.body ?? {}).expectedVersion);
        const removed = await deps.repository.deleteCredential(key, expectedVersion);
        // Explicit deletion is a lifecycle revoke even if another actor
        // already removed the DB row; old workers may still hold its secret.
        await deps.stopSessionsForPrincipal?.(key);
        return ok({ removed });
      }
      if (request.method !== 'PUT') return bad(405, 'method_not_allowed');
      const body = bodyObject(request.body);
      if (body.credentialKind !== undefined && body.credentialKind !== 'api') throw new TypeError('API credential endpoint accepts credentialKind=api only');
      const apiKey = body.key ?? body.apiKey;
      if (typeof apiKey !== 'string') throw new TypeError('key is required');
      if (typeof body.baseUrl !== 'string' || typeof body.model !== 'string') throw new TypeError('baseUrl and model are required');
      const validated = validateApiCredentialInput({ key: apiKey, baseUrl: body.baseUrl, model: body.model });
      const validateEndpoint = deps.validateEndpoint ?? validateApiCredentialEndpoint;
      const baseUrl = (await validateEndpoint(validated.baseUrl.toString())).toString().replace(/\/$/u, '');
      if (!deps.probeApiCredential || typeof request.botCliId !== 'string' || request.botCliId.trim() === '') {
        throw new AgentCredentialProbeError();
      }
      await deps.probeApiCredential({
        cliId: request.botCliId,
        apiKey: validated.key,
        baseUrl,
        model: validated.model,
      });
      const metadata = await deps.repository.putCredential({
        key,
        credentialKind: 'api',
        secret: validated.key,
        baseUrl,
        model: validated.model,
        expectedVersion: positiveVersion(body.expectedVersion),
      });
      await deps.stopSessionsForPrincipal?.(key);
      return ok({ credential: publicCredential(metadata) });
    }

    if (request.path === '/api/agent/model-login') {
      if (request.method !== 'POST') return bad(405, 'method_not_allowed');
      if (!deps.loginService) return bad(503, 'codex_login_unavailable');
      const principalError = await requireActivePrincipal(key, deps.repository);
      if (principalError) return principalError;
      const body = bodyObject(request.body);
      const action = body.action;
      if (action === 'begin') {
        return ok({ task: await deps.loginService.begin(key, { chatType: request.chatType ?? 'group', botCliId: request.botCliId ?? '' }) });
      }
      if (action === 'status') return ok({ task: await deps.loginService.status(key) });
      if (action === 'complete') {
        if (typeof body.taskId !== 'string') throw new TypeError('taskId is required');
        const credential = await deps.loginService.complete(key, body.taskId, positiveVersion(body.expectedVersion));
        return ok({ credential: publicCredential(credential) });
      }
      if (action === 'logout') {
        await deps.loginService.logout(key, typeof body.taskId === 'string' ? body.taskId : undefined);
        return ok({ loggedOut: true });
      }
      throw new TypeError('unknown model-login action');
    }
    return bad(404, 'not_found');
  } catch (error) {
    return mapError(error);
  }
}
