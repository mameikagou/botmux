import { createServer } from 'node:http';
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { request } from 'node:http';
import {
  MEMORY_GATE_CAPABILITY_ENV,
  MEMORY_GATE_CAPABILITY_HEADER,
  MEMORY_GATE_CAPABILITY_SECRET_FILE,
  MEMORY_GATE_URL,
  buildOwnerMemoryGatePlan,
  buildOwnerMemoryGatePlanFromCapability,
  createMemoryGateCapability,
  createMemoryGateReadinessProof,
  MemoryGateCapabilityRegistry,
  probeMemoryGateReadiness,
  readVerifiedMemoryGateReadiness,
  removeMemoryGateReadiness,
  ensureMemoryGateFromEnv,
  loadMemoryGateCapabilitySecretFromConfig,
  loadMemoryGateRuntimeEnv,
  __testOnly_resetMemoryGate,
  verifyMemoryGateCapability,
  MemoryGateServer,
} from '../src/services/openmemory-memory-gate.js';

const SECRET = 'memory-gate-test-secret-0123456789abcdef';
const SESSION = '0123456789abcdef01234567';
const PRINCIPAL = 'fedcba9876543210fedcba98';

function readinessFixture(): { root: string; path: string } {
  const root = mkdtempSync('/tmp/botmux-memory-gate-test-');
  return { root, path: join(root, 'memory-gate-readiness.json') };
}

async function withGate<T>(fn: (gate: MemoryGateServer, readinessPath: string) => Promise<T>): Promise<T> {
  const fixture = readinessFixture();
  const gate = new MemoryGateServer({
    rawApiKey: 'raw-om-key',
    capabilitySecret: SECRET,
    testOnlyPort: 0,
    testOnlyReadinessPath: fixture.path,
  });
  await gate.start();
  try { return await fn(gate, fixture.path); } finally {
    await gate.stop();
    rmSync(fixture.root, { recursive: true, force: true });
  }
}

function httpCall(input: {
  readonly port: number;
  readonly path: string;
  readonly method?: string;
  readonly headers?: Record<string, string>;
  readonly body?: string | Buffer;
}): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({
      host: '127.0.0.1',
      port: input.port,
      path: input.path,
      method: input.method ?? 'GET',
      headers: input.headers,
    }, res => {
      const chunks: Buffer[] = [];
      res.on('data', chunk => chunks.push(Buffer.from(chunk)));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.once('error', reject);
    if (input.body !== undefined) req.end(input.body);
    else req.end();
  });
}

describe('owner-only OpenMemory capability', () => {
  it('binds session, principal and expiry, and rejects replay/expiry', () => {
    const token = createMemoryGateCapability({
      secret: SECRET,
      sessionHash: SESSION,
      principalHash: PRINCIPAL,
      nowMs: 1_000,
      ttlMs: 5_000,
      nonce: 'a'.repeat(32),
    });
    expect(verifyMemoryGateCapability({
      token,
      secret: SECRET,
      sessionHash: SESSION,
      principalHash: PRINCIPAL,
      nowMs: 1_001,
    })?.sessionHash).toBe(SESSION);
    expect(verifyMemoryGateCapability({
      token,
      secret: SECRET,
      sessionHash: '1'.repeat(24),
      principalHash: PRINCIPAL,
      nowMs: 1_001,
    })).toBeUndefined();
    expect(verifyMemoryGateCapability({
      token,
      secret: SECRET,
      sessionHash: SESSION,
      principalHash: PRINCIPAL,
      nowMs: 6_000,
    })).toBeUndefined();
    expect(verifyMemoryGateCapability({
      token: `${token.slice(0, -1)}0`,
      secret: SECRET,
      sessionHash: SESSION,
      principalHash: PRINCIPAL,
      nowMs: 1_001,
    })).toBeUndefined();
  });

  it('creates owner config only for enabled owner principals', () => {
    const plan = buildOwnerMemoryGatePlan({
      principal: { enabled: true, canOpenMemory: true },
      cliId: 'codex',
      sessionHash: SESSION,
      principalHash: PRINCIPAL,
      capabilitySecret: SECRET,
      nowMs: 10_000,
    });
    expect(plan?.mcp.url).toBe(MEMORY_GATE_URL);
    expect(plan?.mcp.capabilityEnvVar).toBe(MEMORY_GATE_CAPABILITY_ENV);
    expect(plan?.capability).not.toContain(SECRET);
    expect(buildOwnerMemoryGatePlan({
      principal: { enabled: false, canOpenMemory: true },
      cliId: 'codex',
      sessionHash: SESSION,
      principalHash: PRINCIPAL,
      capabilitySecret: SECRET,
    })).toBeUndefined();
    expect(() => buildOwnerMemoryGatePlan({
      principal: { enabled: true, canOpenMemory: true },
      cliId: 'opencode',
      sessionHash: SESSION,
      principalHash: PRINCIPAL,
      capabilitySecret: SECRET,
    })).toThrow(/unsupported/);
  });

  it('revalidates capability binding before Podman launch', () => {
    const token = createMemoryGateCapability({
      secret: SECRET,
      sessionHash: SESSION,
      principalHash: PRINCIPAL,
    });
    expect(buildOwnerMemoryGatePlanFromCapability({
      principal: { enabled: true, canOpenMemory: true },
      cliId: 'claude-code',
      sessionHash: SESSION,
      principalHash: PRINCIPAL,
      capability: token,
    })?.mcp.cliId).toBe('claude-code');
    expect(() => buildOwnerMemoryGatePlanFromCapability({
      principal: { enabled: true, canOpenMemory: true },
      cliId: 'claude-code',
      sessionHash: '1'.repeat(24),
      principalHash: PRINCIPAL,
      capability: token,
    })).toThrow(/stale|another/);
  });

  it('slides active capabilities only within a bounded host registry window', () => {
    let now = 0;
    const registry = new MemoryGateCapabilityRegistry({
      clock: () => now,
      slidingWindowMs: 5 * 60_000,
      hardMaxAfterExpiryMs: 12 * 60 * 60_000,
    });
    const token = createMemoryGateCapability({
      secret: SECRET,
      sessionHash: SESSION,
      principalHash: PRINCIPAL,
      nowMs: now,
      ttlMs: 5 * 60_000,
      nonce: 'b'.repeat(32),
    });
    expect(registry.accept({ token, secret: SECRET })).toBeDefined();
    // A long-lived active development session keeps presenting the same
    // signed capability well past the original five-minute expiry.
    for (now = 60_000; now < 12 * 60 * 60_000 + 4 * 60_000; now += 4 * 60_000) {
      expect(registry.accept({ token, secret: SECRET })).toBeDefined();
    }
    now = 12 * 60 * 60_000 + 5 * 60_000 + 1;
    expect(registry.accept({ token, secret: SECRET })).toBeUndefined();
    expect(registry.size).toBe(0);

    // A gate restart has a fresh in-memory registry. The expired token cannot
    // be revived merely because its HMAC remains valid.
    const restarted = new MemoryGateCapabilityRegistry({ clock: () => 6 * 60_000, slidingWindowMs: 5 * 60_000, hardMaxAfterExpiryMs: 12 * 60 * 60_000 });
    expect(restarted.accept({ token, secret: SECRET })).toBeUndefined();
  });

  it('binds only loopback and rejects non-MCP methods before proxying', async () => {
    await withGate(async gate => {
      const port = gate.boundPort!;
      const response = await httpCall({ port, path: '/not-mcp' });
      expect(response.status).toBe(404);
      expect(response.body).not.toContain('raw-om-key');

      const post = (headers: Record<string, string>) => new Promise<number>((resolve, reject) => {
        const req = request({
          host: '127.0.0.1',
          port,
          path: '/mcp',
          method: 'POST',
          headers: { 'content-type': 'application/json', ...headers },
        }, res => {
          res.resume();
          res.on('end', () => resolve(res.statusCode ?? 0));
        });
        req.on('error', reject);
        req.end('{}');
      });
      expect(await post({})).toBe(401);
      expect(await post({ authorization: 'Bearer malformed' })).toBe(403);
      const expired = createMemoryGateCapability({
        secret: SECRET,
        sessionHash: SESSION,
        principalHash: PRINCIPAL,
        nowMs: Date.now() - 2_000,
        ttlMs: 1_000,
      });
      expect(await post({ authorization: `Bearer ${expired}` })).toBe(403);
    });
  });

  it('writes a private signed readiness proof and rejects missing, stale, tampered, or stray listeners', async () => {
    const fixture = readinessFixture();
    const proof = createMemoryGateReadinessProof({ secret: SECRET, port: 18281, nowMs: 1_000 });
    writeFileSync(fixture.path, JSON.stringify(proof), { mode: 0o600 });
    chmodSync(fixture.path, 0o600);
    expect(statSync(fixture.path).mode & 0o777).toBe(0o600);
    expect(readVerifiedMemoryGateReadiness({ secret: SECRET, path: fixture.path, nowMs: 1_001, expectedPort: 18281 })).toBeDefined();
    expect(readVerifiedMemoryGateReadiness({ secret: SECRET, path: fixture.path, nowMs: 32_000, expectedPort: 18281 })).toBeUndefined();
    writeFileSync(fixture.path, JSON.stringify({ ...proof, signature: '0'.repeat(64) }), { mode: 0o600 });
    expect(readVerifiedMemoryGateReadiness({ secret: SECRET, path: fixture.path, nowMs: 1_001, expectedPort: 18281 })).toBeUndefined();
    removeMemoryGateReadiness(fixture.path);
    rmSync(fixture.root, { recursive: true, force: true });

    await withGate(async (gate, path) => {
      expect(await probeMemoryGateReadiness({ secret: SECRET, path, expectedPort: gate.boundPort })).toBe(true);
      const saved = readFileSync(path, 'utf8');
      await gate.stop();
      expect(await probeMemoryGateReadiness({ secret: SECRET, path, expectedPort: gate.boundPort })).toBe(false);
      expect(saved).not.toContain('raw-om-key');
    });

    // A listener on loopback without the signed proof is not adopted.
    const stray = createServer((_req, res) => {
      res.statusCode = 200;
      res.end(JSON.stringify({ version: 'v1', host: '127.0.0.1', port: 1 }));
    });
    await new Promise<void>((resolve, reject) => {
      stray.once('error', reject);
      stray.listen(0, '127.0.0.1', () => resolve());
    });
    const strayPort = (stray.address() as { port: number }).port;
    const strayFixture = readinessFixture();
    writeFileSync(strayFixture.path, JSON.stringify(createMemoryGateReadinessProof({ secret: SECRET, port: strayPort })), { mode: 0o600 });
    expect(await probeMemoryGateReadiness({ secret: SECRET, path: strayFixture.path, expectedPort: strayPort })).toBe(false);
    await new Promise<void>(resolve => stray.close(() => resolve()));
    rmSync(strayFixture.root, { recursive: true, force: true });
  });

  it('retries once when the readiness file generation changes between file and HTTP reads', async () => {
    const fixture = readinessFixture();
    let firstRequest = true;
    let proofNext: ReturnType<typeof createMemoryGateReadinessProof> | undefined;
    const race = createServer((_req, res) => {
      if (firstRequest) {
        firstRequest = false;
        writeFileSync(fixture.path, `${JSON.stringify(proofNext)}\n`, { mode: 0o600 });
      }
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(proofNext));
    });
    await new Promise<void>((resolve, reject) => {
      race.once('error', reject);
      race.listen(0, '127.0.0.1', () => resolve());
    });
    const port = (race.address() as { port: number }).port;
    const nowMs = Date.now();
    const proofFirst = createMemoryGateReadinessProof({ secret: SECRET, port, nowMs, nonce: '1'.repeat(32) });
    proofNext = createMemoryGateReadinessProof({ secret: SECRET, port, nowMs, nonce: '2'.repeat(32) });
    writeFileSync(fixture.path, `${JSON.stringify(proofFirst)}\n`, { mode: 0o600 });
    try {
      expect(await probeMemoryGateReadiness({ secret: SECRET, path: fixture.path, expectedPort: port, nowMs: nowMs + 10 })).toBe(true);
      expect(firstRequest).toBe(false);
    } finally {
      await new Promise<void>(resolve => race.close(() => resolve()));
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it('reads the signer only from a private dedicated file, never from .env/raw credentials', () => {
    const fixture = readinessFixture();
    const envPath = join(fixture.root, '.env');
    const secretPath = join(fixture.root, 'memory-gate-capability-secret');
    writeFileSync(envPath, `OM_API_KEY=raw-key-must-not-be-read\nBOTMUX_MEMORY_GATE_CAPABILITY_SECRET=${'x'.repeat(32)}\n`, { mode: 0o600 });
    writeFileSync(secretPath, `${SECRET}\n`, { mode: 0o600 });
    chmodSync(envPath, 0o600);
    chmodSync(secretPath, 0o600);
    expect(loadMemoryGateCapabilitySecretFromConfig(secretPath)).toBe(SECRET);
    expect(loadMemoryGateCapabilitySecretFromConfig(envPath)).toBeUndefined();
    expect(loadMemoryGateRuntimeEnv({}, envPath, secretPath)).toMatchObject({
      OM_API_KEY: 'raw-key-must-not-be-read',
      BOTMUX_MEMORY_GATE_CAPABILITY_SECRET: SECRET,
    });
    chmodSync(secretPath, 0o644);
    expect(loadMemoryGateCapabilitySecretFromConfig(secretPath)).toBeUndefined();
    expect(loadMemoryGateCapabilitySecretFromConfig(MEMORY_GATE_CAPABILITY_SECRET_FILE + '.missing')).toBeUndefined();
    rmSync(fixture.root, { recursive: true, force: true });
  });

  it('returns 413/408 before closing oversized or incomplete request bodies', async () => {
    await withGate(async gate => {
      const port = gate.boundPort!;
      const capability = createMemoryGateCapability({ secret: SECRET, sessionHash: SESSION, principalHash: PRINCIPAL });
      const oversized = await httpCall({
        port,
        path: '/mcp',
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': '1048577',
          [MEMORY_GATE_CAPABILITY_HEADER]: capability,
        },
        body: '{}',
      });
      // This gate uses its configured maximum; a very large Content-Length is
      // rejected even when the client sends only a short body.
      expect(oversized.status).toBe(413);

      const timeoutFixture = readinessFixture();
      const timeoutGate = new MemoryGateServer({
        rawApiKey: 'raw-om-key',
        capabilitySecret: SECRET,
        testOnlyPort: 0,
        testOnlyReadinessPath: timeoutFixture.path,
        maxBodyBytes: 32,
        requestTimeoutMs: 100,
      });
      await timeoutGate.start();
      try {
        const timeoutResult = await new Promise<number>((resolve, reject) => {
          const req = request({
            host: '127.0.0.1',
            port: timeoutGate.boundPort!,
            path: '/mcp',
            method: 'POST',
            headers: { 'content-type': 'application/json', [MEMORY_GATE_CAPABILITY_HEADER]: capability },
          }, res => { res.resume(); res.once('end', () => resolve(res.statusCode ?? 0)); });
          req.once('error', reject);
          req.write('{');
        });
        expect(timeoutResult).toBe(408);
      } finally {
        await timeoutGate.stop();
        rmSync(timeoutFixture.root, { recursive: true, force: true });
      }
    });
  });

  it('does not adopt EADDRINUSE and keeps production port fixed outside the test seam', async () => {
    const firstFixture = readinessFixture();
    const first = new MemoryGateServer({ rawApiKey: 'raw-om-key', capabilitySecret: SECRET, testOnlyPort: 0, testOnlyReadinessPath: firstFixture.path });
    await first.start();
    const secondFixture = readinessFixture();
    try {
      await expect(ensureMemoryGateFromEnv({ OM_API_KEY: 'raw-om-key', BOTMUX_MEMORY_GATE_CAPABILITY_SECRET: 'legacy-env-secret-must-not-be-used' }, {
        testOnlyPort: first.boundPort,
        testOnlyReadinessPath: secondFixture.path,
        testOnlyCapabilitySecret: SECRET,
      })).rejects.toMatchObject({ code: 'EADDRINUSE' });
      expect(() => new MemoryGateServer({ rawApiKey: 'raw-om-key', capabilitySecret: SECRET, port: 18182 as 18181 })).toThrow(/18181/);
    } finally {
      await first.stop();
      __testOnly_resetMemoryGate();
      rmSync(firstFixture.root, { recursive: true, force: true });
      rmSync(secondFixture.root, { recursive: true, force: true });
    }
  });
});
