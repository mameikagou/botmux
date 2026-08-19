import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { describe, expect, it } from 'vitest';

import { buildSessionRuntimePaths, parsePodmanExecutionConfig } from '../src/execution/podman-execution.js';
import { PodmanExecutionProvider } from '../src/execution/podman-provider.js';

// T2's image is intentionally a test-only local reference. Product config is
// still required to carry an explicit digest and never defaults to this tag.
const T2_IMAGE = process.env.BOTMUX_T2_IMAGE
  ?? 'localhost/botmux-quant-dev@sha256:85ad4d8afc1faa47b3d3b285b14c3ccba4d37788b4d3aa3bbadb21deaa0814e5';

function command(args: readonly string[], timeout = 20_000) {
  return spawnSync('podman', [...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: false,
    timeout,
  });
}

function available(): boolean {
  const info = command(['info', '--format', '{{.Host.Security.Rootless}}']);
  const image = command(['image', 'exists', T2_IMAGE]);
  return info.status === 0 && info.stdout.trim() === 'true' && image.status === 0;
}

const podmanIntegration = available() ? describe : describe.skip;

podmanIntegration('T5 Podman provider integration', () => {
  it('runs the local T2 image with the provider launch spec and removes the container', async () => {
    const root = mkdtempSync('/tmp/botmux-provider-integration-');
    const sourceRepo = `${root}/source`;
    const dataRoot = `${sourceRepo}/apps/quant-qlib/data`;
    const knowledgeRoot = `${sourceRepo}/apps/quant-qlib/knowledge/investment-books`;
    mkdirSync(dataRoot, { recursive: true });
    mkdirSync(knowledgeRoot, { recursive: true });
    writeFileSync(`${dataRoot}/tracked-catalog.txt`, 'mounted data\n');
    writeFileSync(`${knowledgeRoot}/tracked-book.txt`, 'mounted book\n');
    writeFileSync(`${sourceRepo}/apps/quant-qlib/README.md`, 'qlib project\n');
    writeFileSync(`${sourceRepo}/README.md`, 'podman integration\n');
    for (const args of [
      ['init', '--initial-branch', 'main', sourceRepo],
      ['-C', sourceRepo, 'config', 'user.email', 'botmux-test@example.com'],
      ['-C', sourceRepo, 'config', 'user.name', 'botmux test'],
      ['-C', sourceRepo, 'add', '.'],
      ['-C', sourceRepo, 'commit', '-m', 'fixture'],
    ]) {
      const result = spawnSync('git', args, { encoding: 'utf8', stdio: 'ignore', shell: false });
      expect(result.status).toBe(0);
    }
    const config = parsePodmanExecutionConfig({
      type: 'podman',
      image: T2_IMAGE,
      sourceRepo,
      sourceBranch: 'main',
      runtimeRoot: `${root}/runtime`,
      credentialCacheRoot: `${root}/credential-cache`,
      dataRoot,
      knowledgeRoot,
      ownerMemoryGate: '127.0.0.1:18181',
      idleTimeoutMinutes: 10,
      memory: '1g',
      cpus: 1,
    });
    const provider = new PodmanExecutionProvider(config);
    const cases = [
      { sessionId: 'integration-codex', cliId: 'codex', credentialBinding: { kind: 'codex_chatgpt', version: 1 } },
      { sessionId: 'integration-claude', cliId: 'claude-code', credentialBinding: { kind: 'api', version: 1, baseUrl: 'https://api.example.com/v1', model: 'claude-test' }, credentialSecret: 'integration-api-secret-claude' },
      { sessionId: 'integration-pi', cliId: 'pi', credentialBinding: { kind: 'api', version: 1, baseUrl: 'https://api.example.com/v1', model: 'pi-test' }, credentialSecret: 'integration-api-secret-pi' },
      { sessionId: 'integration-opencode', cliId: 'opencode', credentialBinding: { kind: 'api', version: 1, baseUrl: 'https://api.example.com/v1', model: 'opencode-test' }, credentialSecret: 'integration-api-secret-opencode' },
    ] as const;
    for (const testCase of cases) {
      const principal = { larkAppId: 'cli_integration', openId: 'ou_integration' } as const;
      if (testCase.cliId === 'codex') {
        const authPath = buildSessionRuntimePaths(config, principal, testCase.sessionId).codexAuthPath;
        mkdirSync(dirname(authPath), { recursive: true, mode: 0o700 });
        writeFileSync(authPath, JSON.stringify({ tokens: { access_token: 'fixture-token' } }) + '\n', { mode: 0o600 });
        chmodSync(authPath, 0o600);
      }
     const prepared = await provider.prepare({
       sessionId: testCase.sessionId,
       cliId: testCase.cliId,
       principalBinding: principal,
       credentialBinding: testCase.credentialBinding,
     });
      const credentialSecret = 'credentialSecret' in testCase ? testCase.credentialSecret : undefined;
     const launch = provider.launch(prepared, {
       cliId: testCase.cliId,
       bin: testCase.cliId === 'claude-code' ? 'claude' : testCase.cliId,
       args: ['--version'],
        ...(credentialSecret ? { credentialSecret } : {}),
     });
     const argv = launch.args.join('\n');
      if (credentialSecret) {
        expect(argv).not.toContain(credentialSecret);
        expect(launch.env.AGENT_API_KEY).toBe(credentialSecret);
        expect(readFileSync(prepared.credential.providerConfig!.path, 'utf8')).not.toContain(credentialSecret);
      }
      const result = spawnSync(launch.bin, [...launch.args], {
        cwd: launch.cwd,
        env: { ...process.env, ...launch.env },
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        shell: false,
        timeout: 60_000,
      });
      expect(result.status, result.stderr).toBe(0);
      expect(`${result.stdout}${result.stderr}`).toMatch(/smoke|codex|claude|pi|opencode|version|ok/iu);
      expect(readlinkSync(`${prepared.hostWorkingDir}/apps/quant-qlib/data`)).toBe('/shared/quant-data');
      expect(readlinkSync(`${prepared.hostWorkingDir}/apps/quant-qlib/knowledge/investment-books`))
        .toBe('/knowledge/investment-books');
      const state = await provider.inspect(prepared);
      expect(['missing', 'exited', 'stopped']).toContain(state.status);
      await provider.destroyRuntime(prepared, { authorized: true });
    }
  }, 90_000);
});
