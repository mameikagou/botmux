import { mkdtempSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import {
  acquirePodmanResourceLease,
  PODMAN_GLOBAL_CPU_BUDGET,
  PODMAN_GLOBAL_MAX_CONTAINERS,
  PODMAN_GLOBAL_MEMORY_BUDGET_BYTES,
  PODMAN_MAX_CONTAINER_CPUS,
  PODMAN_MAX_CONTAINER_MEMORY_BYTES,
  podmanMemoryBytes,
} from '../src/execution/podman-resource-admission.js';

describe('Podman resource admission', () => {
  it('parses binary and decimal memory quantities', () => {
    expect(podmanMemoryBytes('4g')).toBe(4 * 1000 ** 3);
    expect(podmanMemoryBytes('4Gi')).toBe(4 * 1024 ** 3);
  });

  it('bounds one guest and reclaims a dead worker lease', () => {
    const root = mkdtempSync('/tmp/botmux-resource-admission-');
    const first = acquirePodmanResourceLease(
      root,
      'aaaaaaaaaaaaaaaaaaaaaaaa',
      PODMAN_MAX_CONTAINER_MEMORY_BYTES,
      PODMAN_MAX_CONTAINER_CPUS,
      { pid: 999_991, pidStartTime: 'gone' },
    );
    expect(() => acquirePodmanResourceLease(
      root,
      'bbbbbbbbbbbbbbbbbbbbbbbb',
      PODMAN_MAX_CONTAINER_MEMORY_BYTES,
      PODMAN_MAX_CONTAINER_CPUS,
      { maxContainers: 1 },
    )).not.toThrow();
    first.release();
  });

  it('enforces the shared memory, CPU, and count budget', () => {
    const root = mkdtempSync('/tmp/botmux-resource-admission-budget-');
    const leases = [
      acquirePodmanResourceLease(root, 'aaaaaaaaaaaaaaaaaaaaaaaa', 4 * 1024 ** 3, 2),
      acquirePodmanResourceLease(root, 'bbbbbbbbbbbbbbbbbbbbbbbb', 4 * 1024 ** 3, 2),
      acquirePodmanResourceLease(root, 'cccccccccccccccccccccccc', 4 * 1024 ** 3, 2),
    ];
    expect(leases).toHaveLength(PODMAN_GLOBAL_MAX_CONTAINERS);
    expect(() => acquirePodmanResourceLease(
      root,
      'dddddddddddddddddddddddd',
      1,
      1,
    )).toThrow(/guest capacity reached/);
    expect(PODMAN_GLOBAL_MEMORY_BUDGET_BYTES).toBe(12 * 1024 ** 3);
    expect(PODMAN_GLOBAL_CPU_BUDGET).toBe(6);
    for (const lease of leases) lease.release();
  });
});
