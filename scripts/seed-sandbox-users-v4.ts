#!/usr/bin/env tsx
/**
 * Seed the three explicitly approved guest identities into the V4 stable-user
 * registry. The command is dry-run unless --commit is supplied and never
 * prints credential material or database rows containing ciphertext.
 */
import { applyAgentPrincipalMigration, AgentPrincipalRepository, createAgentPrincipalPool } from '../src/services/agent-principal-store.js';
import { applySandboxUserRegistryMigration, SandboxUserRegistryRepository } from '../src/services/sandbox-user-registry.js';
import { credentialFingerprint, loadCredentialMasterKey } from '../src/services/agent-principal-crypto.js';

type GuestSeed = {
  readonly sandboxUserId: string;
  readonly key: { readonly larkAppId: string; readonly openId: string };
  readonly harness: 'codex' | 'claude-code' | 'pi' | 'opencode';
  /** Owner-native API credential to copy when the guest legacy row is empty. */
  readonly source?: { readonly larkAppId: string; readonly openId: string };
};

const GUESTS: readonly GuestSeed[] = [
  {
    sandboxUserId: 'guest-test-736209',
    key: { larkAppId: 'cli_aacfbf298b385cc4', openId: 'ou_5ec0b59085714a45a2de30b41cd7c952' },
    harness: 'codex',
  },
  {
    sandboxUserId: 'guest-yang',
    key: { larkAppId: 'cli_aacfbf298b385cc4', openId: 'ou_f0718f0c9972a64033701d9d950444fe' },
    harness: 'codex',
  },
  {
    sandboxUserId: 'guest-yang',
    key: { larkAppId: 'cli_aabc766a0721dcd6', openId: 'ou_bac32af39b797b84092a3725d5e42b05' },
    harness: 'claude-code',
    source: { larkAppId: 'cli_aabc766a0721dcd6', openId: 'ou_42921afbce9eedd1cda81e6eca6e5aac' },
  },
  {
    sandboxUserId: 'guest-claude',
    key: { larkAppId: 'cli_aacf71b1adb81cef', openId: 'ou_a730c52f8c4d196cc210a3fa22d73c6f' },
    harness: 'claude-code',
    source: { larkAppId: 'cli_aacf71b1adb81cef', openId: 'ou_15d49ca5135d3701553da6606c796d3f' },
  },
];

const commit = process.argv.slice(2).includes('--commit');
const databaseUrl = process.env.BOTMUX_AGENT_DATABASE_URL;
if (!databaseUrl?.trim()) throw new Error('BOTMUX_AGENT_DATABASE_URL is required');

process.stdout.write(JSON.stringify({
  dryRun: !commit,
  users: [...new Set(GUESTS.map(seed => seed.sandboxUserId))],
  identities: GUESTS.map(seed => ({ ...seed.key, sandboxUserId: seed.sandboxUserId, harness: seed.harness })),
  sourceCredentials: GUESTS.filter(seed => seed.source).map(seed => ({
    target: seed.key,
    source: seed.source,
    hasCredential: 'unknown',
  })),
}) + '\n');
if (!commit) process.exit(0);

const pool = createAgentPrincipalPool(databaseUrl);
const masterKey = loadCredentialMasterKey();
const legacy = new AgentPrincipalRepository(pool, masterKey);
const registry = new SandboxUserRegistryRepository(pool, masterKey);
try {
  await applyAgentPrincipalMigration(pool);
  await applySandboxUserRegistryMigration(pool);
  for (const sandboxUserId of [...new Set(GUESTS.map(seed => seed.sandboxUserId))]) {
    await registry.createUser({ sandboxUserId, enabled: true, canOpenMemory: false, executionMode: 'podman' });
  }
  const copied: Array<{ readonly target: { readonly larkAppId: string; readonly openId: string }; readonly hasCredential: boolean; readonly fingerprint?: string }> = [];
  for (const seed of GUESTS) {
    // This decrypts/re-encrypts inside the service boundary. The old app/open
    // row remains for rolling downgrade, but all new V4 launches read only the
    // stable user+harness row.
    await registry.migrateLegacyPrincipal(seed);
    if (seed.source) {
      const existing = await registry.getCredential({ sandboxUserId: seed.sandboxUserId }, seed.harness);
      if (existing) {
        copied.push({ target: seed.key, hasCredential: true });
        continue;
      }
      try {
        const source = await legacy.readSecret(seed.source, undefined, seed.harness);
        const written = await registry.putCredential({
          user: { sandboxUserId: seed.sandboxUserId },
          harness: seed.harness,
          credentialKind: source.metadata.credentialKind,
          secret: source.secret,
          ...(source.metadata.baseUrl ? { baseUrl: source.metadata.baseUrl } : {}),
          ...(source.metadata.model ? { model: source.metadata.model } : {}),
        });
        copied.push({ target: seed.key, hasCredential: true, fingerprint: written.keyFingerprint ?? credentialFingerprint(source.secret) });
      } catch (error) {
        if ((error as { code?: unknown } | undefined)?.code !== 'credential_missing') throw error;
        copied.push({ target: seed.key, hasCredential: false });
      }
    }
  }
  process.stdout.write(JSON.stringify({ copiedCredentials: copied }) + '\n');
} finally {
  await pool.end?.();
}
