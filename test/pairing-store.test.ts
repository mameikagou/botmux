/**
 * Pairing-login store: device-code style browser ↔ Feishu identity binding.
 * Run: pnpm vitest run test/pairing-store.test.ts
 */
import { lstatSync, mkdtempSync, readFileSync, symlinkSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, beforeEach } from 'vitest';
import {
  createAgentPairingSession, createPairing, claimPairing, getAgentPairingSession,
  getPairingStatus, consumePairing, getConsumedPairingPrincipal, revokeAgentPairingSession,
  PairingCapacityError,
} from '../src/services/pairing-store.js';

let dataDir: string;
beforeEach(() => { dataDir = mkdtempSync(join(tmpdir(), 'botmux-pairing-')); });

describe('pairing-store', () => {
  it('full happy path: start → claim → consume', () => {
    const p = createPairing(dataDir);
    expect(p.code).toMatch(/^[A-Z2-9]{8}$/);
    expect(p.browserToken.length).toBeGreaterThan(20);
    expect(getPairingStatus(dataDir, p.pairingId, p.browserToken)).toEqual({ status: 'pending' });

    const claim = claimPairing(dataDir, p.code, { openId: 'ou_1', unionId: 'on_1', name: '张三' });
    expect(claim).toEqual({ ok: true, pairingId: p.pairingId });

    expect(getPairingStatus(dataDir, p.pairingId, p.browserToken)).toEqual({ status: 'claimed', claimedBy: { openId: 'ou_1', unionId: 'on_1', name: '张三' } });

    const consumed = consumePairing(dataDir, p.pairingId, p.browserToken);
    expect(consumed).toEqual({ ok: true, claimedBy: { openId: 'ou_1', unionId: 'on_1', name: '张三' } });
    expect(getConsumedPairingPrincipal(dataDir, p.pairingId, p.browserToken)).toEqual({ openId: 'ou_1', unionId: 'on_1', name: '张三' });
    expect(getConsumedPairingPrincipal(dataDir, p.pairingId, 'wrong-token')).toBeUndefined();
    // single-use
    expect(consumePairing(dataDir, p.pairingId, p.browserToken)).toEqual({ ok: false, reason: 'already_consumed' });
  });

  it('code is case-insensitive and trimmed on claim', () => {
    const p = createPairing(dataDir);
    expect(claimPairing(dataDir, `  ${p.code.toLowerCase()}  `, { openId: 'ou_1' }).ok).toBe(true);
  });

  it('claim fails for unknown / already-claimed code', () => {
    expect(claimPairing(dataDir, 'NOTACODE', { openId: 'ou_1' })).toEqual({ ok: false, reason: 'not_found' });
    const p = createPairing(dataDir);
    expect(claimPairing(dataDir, p.code, { openId: 'ou_1' }).ok).toBe(true);
    expect(claimPairing(dataDir, p.code, { openId: 'ou_2' })).toEqual({ ok: false, reason: 'already_claimed' });
  });

  it('expired pairing cannot be claimed or seen', () => {
    const p = createPairing(dataDir, 1000, 1_000_000);
    // 2s later — past the 1s TTL
    expect(claimPairing(dataDir, p.code, { openId: 'ou_1' }, 1_002_000)).toEqual({ ok: false, reason: 'not_found' });
    expect(getPairingStatus(dataDir, p.pairingId, p.browserToken, 1_002_000)).toEqual({ status: 'not_found' });
  });

  it('browserToken gates status and consume', () => {
    const p = createPairing(dataDir);
    claimPairing(dataDir, p.code, { openId: 'ou_1' });
    expect(getPairingStatus(dataDir, p.pairingId, 'wrong-token')).toEqual({ status: 'not_found' });
    expect(consumePairing(dataDir, p.pairingId, 'wrong-token')).toEqual({ ok: false, reason: 'not_found' });
  });

  it('consume requires a claimed pairing', () => {
    const p = createPairing(dataDir);
    expect(consumePairing(dataDir, p.pairingId, p.browserToken)).toEqual({ ok: false, reason: 'not_claimed' });
  });

  it('codes are unique across concurrent pairings', () => {
    const codes = new Set(Array.from({ length: 50 }, () => createPairing(dataDir).code));
    expect(codes.size).toBe(50);
  });

  it('serializes real child-process read-modify-write operations', async () => {
    const modulePath = join(process.cwd(), 'src/services/pairing-store.ts');
    const script = `import { createPairing } from ${JSON.stringify(modulePath)}; createPairing(process.argv[1]);`;
    const runChild = (): Promise<void> => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ['--import', 'tsx', '--eval', script, dataDir], {
        cwd: process.cwd(),
        stdio: ['ignore', 'ignore', 'pipe'],
      });
      let stderr = '';
      child.stderr.on('data', chunk => { stderr += String(chunk); });
      child.once('error', reject);
      child.once('close', code => code === 0 ? resolve() : reject(new Error(stderr || `child exited ${String(code)}`)));
    });
    await Promise.all(Array.from({ length: 8 }, runChild));
    const stored = JSON.parse(readFileSync(join(dataDir, 'pairings.json'), 'utf8')) as Record<string, unknown>;
    expect(Object.keys(stored)).toHaveLength(8);
  });

  it('creates an app-scoped revocable session with private storage and expiry', () => {
    const p = createPairing(dataDir);
    claimPairing(dataDir, p.code, { openId: 'ou_1', larkAppId: 'cli_a' });
    const consumed = consumePairing(dataDir, p.pairingId, p.browserToken);
    if (!consumed.ok) throw new Error('pairing did not consume');
    const session = createAgentPairingSession(dataDir, consumed.claimedBy, 1_000, 10_000);
    expect(getAgentPairingSession(dataDir, session.sessionToken, 10_999)?.principal).toEqual({ openId: 'ou_1', larkAppId: 'cli_a' });
    expect(getAgentPairingSession(dataDir, session.sessionToken, 11_000)).toBeUndefined();
    const live = createAgentPairingSession(dataDir, consumed.claimedBy, 10_000, 20_000);
    expect(revokeAgentPairingSession(dataDir, live.sessionToken, 20_001)).toBe(true);
    expect(getAgentPairingSession(dataDir, live.sessionToken, 20_001)).toBeUndefined();
    expect(lstatSync(join(dataDir, 'pairings.json')).isFile()).toBe(true);
    expect(lstatSync(join(dataDir, 'pairing-sessions.json')).isFile()).toBe(true);
  });

  it('rejects a symlinked pairings file', () => {
    const target = join(dataDir, 'real.json');
    const path = join(dataDir, 'pairings.json');
    symlinkSync(target, path);
    expect(() => createPairing(dataDir)).toThrow(/regular file|trusted/);
  });

  it('prunes expired entries and enforces the live pairing capacity atomically', () => {
    const first = createPairing(dataDir, 1_000, 1_000, 1);
    expect(() => createPairing(dataDir, 1_000, 1_500, 1)).toThrow(PairingCapacityError);
    const second = createPairing(dataDir, 1_000, 2_001, 1);
    expect(second.pairingId).not.toBe(first.pairingId);
  });
});
