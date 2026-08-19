import type { IncomingMessage } from 'node:http';

/** The public pairing endpoints are deliberately small, but they sit before
 * the dashboard-auth gate. Keep their abuse budget local to this dashboard
 * process so an unauthenticated caller cannot turn JSON store operations into
 * an unbounded disk workload. */
export type AgentPairingRateLimitRoute = 'start' | 'status' | 'consume';

type RatePolicy = Readonly<{
  windowMs: number;
  maxRequests: number;
}>;

const POLICIES: Record<AgentPairingRateLimitRoute, RatePolicy> = {
  // Starting a pairing writes a high-entropy bearer to disk, so keep this
  // intentionally tighter than the polling endpoints.
  start: { windowMs: 60_000, maxRequests: 6 },
  status: { windowMs: 60_000, maxRequests: 30 },
  consume: { windowMs: 60_000, maxRequests: 10 },
};
const MAX_KEYS = 4_096;

type Bucket = {
  readonly timestamps: number[];
  lastSeenAt: number;
};

export type AgentPairingRateLimitDecision = Readonly<{
  allowed: boolean;
  retryAfterSeconds: number;
}>;

/** A bounded sliding-window limiter. It is intentionally process-local: the
 * pairing store itself remains the cross-process authority for capacity and
 * atomicity, while this layer absorbs repeated anonymous requests cheaply. */
export class AgentPairingRateLimiter {
  private readonly buckets = new Map<string, Bucket>();

  constructor(private readonly now: () => number = Date.now) {}

  check(clientAddress: string, route: AgentPairingRateLimitRoute): AgentPairingRateLimitDecision {
    const policy = POLICIES[route];
    const now = this.now();
    const key = `${clientAddress}\u0000${route}`;
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = { timestamps: [], lastSeenAt: now };
      this.buckets.set(key, bucket);
    }
    bucket.lastSeenAt = now;
    const cutoff = now - policy.windowMs;
    while (bucket.timestamps.length > 0 && bucket.timestamps[0] <= cutoff) bucket.timestamps.shift();
    if (bucket.timestamps.length >= policy.maxRequests) {
      const oldest = bucket.timestamps[0] ?? now;
      return {
        allowed: false,
        retryAfterSeconds: Math.max(1, Math.ceil((oldest + policy.windowMs - now) / 1000)),
      };
    }
    bucket.timestamps.push(now);
    this.evictIfNeeded();
    return { allowed: true, retryAfterSeconds: 0 };
  }

  /** Useful for deterministic tests and for bounded memory after long idle
   * periods. Production callers do not need to invoke this explicitly. */
  prune(): void {
    const cutoff = this.now() - 60_000;
    for (const [key, bucket] of this.buckets) {
      if (bucket.lastSeenAt <= cutoff) this.buckets.delete(key);
    }
  }

  private evictIfNeeded(): void {
    if (this.buckets.size <= MAX_KEYS) return;
    this.prune();
    while (this.buckets.size > MAX_KEYS) {
      let oldestKey: string | undefined;
      let oldest = Number.POSITIVE_INFINITY;
      for (const [key, bucket] of this.buckets) {
        if (bucket.lastSeenAt < oldest) {
          oldest = bucket.lastSeenAt;
          oldestKey = key;
        }
      }
      if (!oldestKey) break;
      this.buckets.delete(oldestKey);
    }
  }
}

export const agentPairingRateLimiter = new AgentPairingRateLimiter();

export function pairingRateLimitRoute(pathname: string): AgentPairingRateLimitRoute | undefined {
  if (pathname === '/api/agent/pairing/start') return 'start';
  if (pathname === '/api/agent/pairing/status') return 'status';
  if (pathname === '/api/agent/pairing/consume') return 'consume';
  return undefined;
}

/**
 * Return the transport peer by default. X-Forwarded-For is intentionally not
 * trusted here: this dashboard has no configured trusted-proxy chain, and an
 * arbitrary header would let a caller mint unlimited rate-limit identities.
 * A future trusted proxy adapter can replace this helper at that boundary.
 */
export function pairingClientAddress(req: IncomingMessage): string {
  const remote = req.socket?.remoteAddress;
  if (typeof remote !== 'string' || remote.trim() === '') return 'unknown';
  return remote.trim().replace(/^::ffff:/u, '');
}
