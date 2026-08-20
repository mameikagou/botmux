import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { buildPastaNetworkPlan } from '../src/execution/podman-execution.js';
import {
  PodmanUserPodManager,
  type PodmanPodCommandResult,
} from '../src/execution/podman-user-pod.js';

function fakePodman() {
  const calls: string[][] = [];
  const pods = new Map<string, { status: string; labels: Record<string, string> }>();
  const runner = async (_command: string, args: readonly string[]): Promise<PodmanPodCommandResult> => {
    calls.push([...args]);
    const name = args[args.length - 1]!;
    if (args[0] === 'pod' && args[1] === 'inspect') {
      const pod = pods.get(name);
      if (!pod) return { status: 1, stdout: '', stderr: 'no such pod' };
      return {
        status: 0,
        stdout: JSON.stringify({ Id: `id-${name}`, State: { Status: pod.status }, Config: { Labels: pod.labels } }),
        stderr: '',
      };
    }
    if (args[0] === 'pod' && args[1] === 'create') {
      const podName = args.find(arg => arg.startsWith('--name='))!.slice('--name='.length);
      const labels: Record<string, string> = {};
      for (const arg of args.filter(item => item.startsWith('--label='))) {
        const [key, ...rest] = arg.slice('--label='.length).split('=');
        labels[key!] = rest.join('=');
      }
      pods.set(podName, { status: 'Running', labels });
      return { status: 0, stdout: podName, stderr: '' };
    }
    if (args[0] === 'pod' && args[1] === 'start') {
      const pod = pods.get(name);
      if (pod) pod.status = 'Running';
      return pod ? { status: 0, stdout: '', stderr: '' } : { status: 1, stdout: '', stderr: 'no such pod' };
    }
    if (args[0] === 'pod' && args[1] === 'stop') {
      const pod = pods.get(name);
      if (pod) pod.status = 'Stopped';
      return pod ? { status: 0, stdout: '', stderr: '' } : { status: 1, stdout: '', stderr: 'no such pod' };
    }
    if (args[0] === 'pod' && args[1] === 'rm') {
      pods.delete(name);
      return { status: 0, stdout: '', stderr: '' };
    }
    return { status: 0, stdout: '', stderr: '' };
  };
  return { calls, pods, runner };
}

function makeManager(root: string, runner: ReturnType<typeof fakePodman>['runner']): PodmanUserPodManager {
  return new PodmanUserPodManager(root, {
    commandRunner: runner,
    pid: process.pid,
    pidStartTime: undefined,
    hostEnv: { PATH: '/usr/bin', HOME: '/home/test' },
  });
}

describe('PodmanUserPodManager', () => {
  it('derives deterministic, generation-scoped names without exposing the user id', () => {
    const root = mkdtempSync('/tmp/botmux-user-pod-binding-');
    const manager = makeManager(root, fakePodman().runner);
    const first = manager.binding({ larkAppId: 'app', sandboxUserId: 'user-a', podGeneration: 1, canOpenMemory: false });
    const same = manager.binding({ larkAppId: 'app-2', sandboxUserId: 'user-a', podGeneration: 1, canOpenMemory: false });
    const next = manager.binding({ larkAppId: 'app', sandboxUserId: 'user-a', podGeneration: 2, canOpenMemory: false });
    const other = manager.binding({ larkAppId: 'app', sandboxUserId: 'user-b', podGeneration: 1, canOpenMemory: false });
    expect(same.larkAppId).toBe('app-2');
    expect(same.podName).toBe(first.podName);
    expect(same.metadataRoot).toBe(first.metadataRoot);
    expect(next.podName).not.toBe(first.podName);
    expect(other.podName).not.toBe(first.podName);
    expect(first.podName).not.toContain('user-a');
    expect(first.metadataRoot).toContain('g1');
  });

  it('shares one pod identity for the same sandbox user across Lark apps', () => {
    const root = mkdtempSync('/tmp/botmux-user-pod-app-scope-');
    const manager = makeManager(root, fakePodman().runner);
    const first = manager.binding({ larkAppId: 'cli_primary', sandboxUserId: 'stable-user', podGeneration: 1, canOpenMemory: false });
    const second = manager.binding({ larkAppId: 'cli_secondary', sandboxUserId: 'stable-user', podGeneration: 1, canOpenMemory: false });
    expect(second.podName).toBe(first.podName);
    expect(second.metadataRoot).toBe(first.metadataRoot);
  });

  it('creates exactly one labelled pod under a cross-worker lock and cold-starts it', async () => {
    const root = mkdtempSync('/tmp/botmux-user-pod-create-');
    const fake = fakePodman();
    const manager = makeManager(root, fake.runner);
    const binding = manager.binding({ larkAppId: 'app', sandboxUserId: 'user-a', podGeneration: 3, canOpenMemory: false });
    const network = buildPastaNetworkPlan(false);
    const [first, second] = await Promise.all([manager.ensure(binding, network), manager.ensure(binding, network)]);
    expect(first.status).toBe('running');
    expect(second.status).toBe('running');
    expect(fake.calls.filter(args => args[0] === 'pod' && args[1] === 'create')).toHaveLength(1);
    const create = fake.calls.find(args => args[0] === 'pod' && args[1] === 'create')!;
    expect(create).toContain(`--name=${binding.podName}`);
    expect(create).toContain('--network=pasta:--no-map-gw');
    expect(create).toContain(`--label=io.botmux.sandbox-user-hash=${binding.sandboxUserHash}`);
    expect(create).toContain('--label=io.botmux.network-profile=guest');
    expect(create.join('\n')).not.toContain(binding.sandboxUserId);
    expect(existsSync(join(binding.metadataRoot, 'pod.json'))).toBe(true);
    expect(JSON.parse(readFileSync(join(binding.metadataRoot, 'pod.json'), 'utf8'))).toMatchObject({
      podName: binding.podName,
      podGeneration: 3,
    });

    fake.pods.get(binding.podName)!.status = 'Stopped';
    const cold = await manager.ensure(binding, network);
    expect(cold.status).toBe('running');
    expect(fake.calls.some(args => args[0] === 'pod' && args[1] === 'start')).toBe(true);
  });

  it('keeps session leases independent and removes only stale leases', async () => {
    const root = mkdtempSync('/tmp/botmux-user-pod-lease-');
    const fake = fakePodman();
    const manager = makeManager(root, fake.runner);
    const binding = manager.binding({ larkAppId: 'app', sandboxUserId: 'user-a', podGeneration: 1, canOpenMemory: false });
    await manager.ensure(binding, buildPastaNetworkPlan(false));
    const release = manager.acquireSession(binding, 'aaaaaaaaaaaaaaaaaaaaaaaa');
    expect(() => manager.acquireSession(binding, 'aaaaaaaaaaaaaaaaaaaaaaaa')).toThrow(/already owns/);
    await manager.stopIfIdle(binding);
    expect(fake.pods.get(binding.podName)!.status).toBe('Running');
    release();
    await manager.stopIfIdle(binding);
    expect(fake.pods.get(binding.podName)!.status).toBe('Stopped');
    await manager.remove(binding);
    expect(fake.pods.has(binding.podName)).toBe(false);
    expect(existsSync(binding.metadataRoot)).toBe(true);
  });

  it('fails closed when an existing name is not this user/generation', async () => {
    const root = mkdtempSync('/tmp/botmux-user-pod-label-');
    const fake = fakePodman();
    const manager = makeManager(root, fake.runner);
    const binding = manager.binding({ larkAppId: 'app', sandboxUserId: 'user-a', podGeneration: 1, canOpenMemory: false });
    fake.pods.set(binding.podName, {
      status: 'Running',
      labels: {
        'io.botmux.managed': 'true',
        'io.botmux.sandbox-user-hash': 'some-other-user',
        'io.botmux.pod-generation': '1',
        'io.botmux.network-profile': 'guest',
      },
    });
    await expect(manager.ensure(binding, buildPastaNetworkPlan(false))).rejects.toThrow(/not the expected BotMux user pod/);
  });

  it('maps the host USA-08 proxy into the pod without copying Clash state', async () => {
    const root = mkdtempSync('/tmp/botmux-user-pod-proxy-');
    const fake = fakePodman();
    let verified = 0;
    const manager = new PodmanUserPodManager(root, {
      commandRunner: fake.runner,
      verifyGuestProxy: true,
      guestProxy: {
        host: '169.254.1.1',
        httpPort: 17890,
        socksPort: 17890,
        selectedRoute: 'USA-08',
        verify: async () => { verified += 1; },
      },
      hostEnv: { PATH: '/usr/bin' },
    });
    const binding = manager.binding({ larkAppId: 'app', sandboxUserId: 'stable-user', podGeneration: 1, canOpenMemory: false });
    await manager.ensure(binding, buildPastaNetworkPlan(false));
    expect(verified).toBe(1);
    const create = fake.calls.find(args => args[0] === 'pod' && args[1] === 'create')!;
    expect(create).toContain('--network=pasta:-T,none,-U,none,--map-host-loopback,169.254.1.1');
    expect(create).toContain('--label=io.botmux.proxy-route=USA-08');
    expect(create.join('\n')).not.toContain('config.yaml');
    expect(create.join('\n')).not.toContain('secret');
    expect(create.join('\n')).not.toContain(':7890');
  });
});
