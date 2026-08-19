import type { DaemonSession } from '../core/types.js';
import type { AgentPrincipalKey } from './agent-principal-store.js';

/** Stop all live sessions carrying the exact app-scoped principal binding. */
export async function stopSessionsForPrincipal(
  sessions: Iterable<DaemonSession>,
  key: AgentPrincipalKey,
  stop: (session: DaemonSession) => Promise<void> | void,
  options: {
    /** Persist the cleared non-secret binding for a future rebind. */
    readonly persist?: (session: DaemonSession['session']) => void;
  } = {},
): Promise<number> {
  let stopped = 0;
  for (const ds of sessions) {
    const binding = ds.session.principalBinding;
    const openId = binding?.openId ?? binding?.open_id;
    if (!binding || binding.larkAppId !== key.larkAppId || openId !== key.openId) continue;
    await stop(ds);
    // A stop caused by disable/delete/rotation must not leave a stale frozen
    // binding that bricks the next cold start. Secrets are transient too.
    ds.session.principalBinding = undefined;
    ds.session.credentialBinding = undefined;
    ds.credentialSecret = undefined;
    options.persist?.(ds.session);
    stopped += 1;
  }
  return stopped;
}

export function sessionMatchesPrincipal(ds: Pick<DaemonSession, 'session'>, key: AgentPrincipalKey): boolean {
  const binding = ds.session.principalBinding;
  return !!binding && binding.larkAppId === key.larkAppId && (binding.openId ?? binding.open_id) === key.openId;
}
