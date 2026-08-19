import { describe, expect, it } from 'vitest';
import {
  AgentPairingRateLimiter,
  pairingClientAddress,
  pairingRateLimitRoute,
} from '../src/services/agent-pairing-rate-limit.js';

describe('agent pairing endpoint rate limit', () => {
  it('returns a retryable denial after the per-IP start budget', () => {
    let now = 1_000;
    const limiter = new AgentPairingRateLimiter(() => now);
    for (let i = 0; i < 6; i++) expect(limiter.check('192.0.2.10', 'start').allowed).toBe(true);
    const denied = limiter.check('192.0.2.10', 'start');
    expect(denied).toEqual({ allowed: false, retryAfterSeconds: 60 });
    now += 60_001;
    expect(limiter.check('192.0.2.10', 'start').allowed).toBe(true);
  });

  it('keeps status and consume budgets independent from start', () => {
    const limiter = new AgentPairingRateLimiter(() => 1_000);
    for (let i = 0; i < 6; i++) limiter.check('192.0.2.11', 'start');
    expect(limiter.check('192.0.2.11', 'start').allowed).toBe(false);
    expect(limiter.check('192.0.2.11', 'status').allowed).toBe(true);
    expect(limiter.check('192.0.2.11', 'consume').allowed).toBe(true);
  });

  it('uses the socket peer and ignores an untrusted forwarded address', () => {
    const req = {
      socket: { remoteAddress: '::ffff:198.51.100.4' },
      headers: { 'x-forwarded-for': '203.0.113.99' },
    } as any;
    expect(pairingClientAddress(req)).toBe('198.51.100.4');
    expect(pairingRateLimitRoute('/api/agent/pairing/start')).toBe('start');
    expect(pairingRateLimitRoute('/api/agent/pairing/status')).toBe('status');
    expect(pairingRateLimitRoute('/api/agent/pairing/consume')).toBe('consume');
    expect(pairingRateLimitRoute('/api/agent/pairing/revoke')).toBeUndefined();
  });
});
