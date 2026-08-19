import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

import { buildPastaNetworkPlan } from '../src/execution/podman-execution.js';

// This image is only used when it is already present locally.  The probe must
// not pull an image or change a user's image store as a side effect of tests.
const PROBE_IMAGE =
  'docker.io/library/alpine@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce';

function commandSucceeded(args: readonly string[]): boolean {
  const result = spawnSync('podman', [...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 10_000,
  });
  return result.error === undefined && result.status === 0;
}

function rootlessPodmanAvailable(): boolean {
  const result = spawnSync('podman', ['info', '--format', '{{.Host.Security.Rootless}}'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 10_000,
  });
  return result.error === undefined
    && result.status === 0
    && result.stdout.trim() === 'true'
    && commandSucceeded(['image', 'exists', PROBE_IMAGE]);
}

function runPodman(args: readonly string[]): string {
  const result = spawnSync('podman', [...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 30_000,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error([
      `podman ${args.join(' ')} exited with ${String(result.status)}`,
      result.stdout,
      result.stderr,
    ].filter(Boolean).join('\n'));
  }
  return result.stdout;
}

const podmanIntegration = rootlessPodmanAvailable() ? describe : describe.skip;

podmanIntegration('rootless Podman pasta probes', () => {
  const aliases = [
    "grep -Eq '(^|[[:space:]])127\\.0\\.0\\.1[[:space:]]+host\\.containers\\.internal([[:space:]]|$)' /etc/hosts",
    "grep -Eq '(^|[[:space:]])127\\.0\\.0\\.1[[:space:]]+host\\.docker\\.internal([[:space:]]|$)' /etc/hosts",
  ].join(' && ');

  it('keeps friend internet access and loopback-only host aliases', () => {
    const plan = buildPastaNetworkPlan({ can_openmemory: false });
    const output = runPodman([
      'run',
      '--rm',
      `--network=${plan.networkOption}`,
      ...plan.addHosts.map(host => `--add-host=${host}`),
      PROBE_IMAGE,
      'sh',
      '-c',
      `${aliases} && wget -q -T 10 -O /dev/null https://example.com && printf 'friend-ok\\n'`,
    ]);
    expect(output.trim()).toBe('friend-ok');
  }, 30_000);

  it('starts the owner MemoryGate network option without touching the live port', () => {
    const plan = buildPastaNetworkPlan({ canOpenMemory: true });
    const output = runPodman([
      'run',
      '--rm',
      `--network=${plan.networkOption}`,
      ...plan.addHosts.map(host => `--add-host=${host}`),
      PROBE_IMAGE,
      'sh',
      '-c',
      `${aliases} && printf 'owner-ok\\n'`,
    ]);
    expect(output.trim()).toBe('owner-ok');
  }, 30_000);
});
