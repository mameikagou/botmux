/**
 * Cross-process admission for guest containers.
 *
 * Botmux workers are separate Node processes, so an in-memory semaphore does
 * not bound the fleet. A tiny lease directory under the configured runtime
 * root gives every worker the same view without introducing another service.
 * Leases are reclaimed when their owning worker is gone.
 */

import {
  statfsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { join, resolve } from 'node:path';

export const PODMAN_MAX_CONTAINER_MEMORY_BYTES = 4 * 1024 ** 3;
export const PODMAN_MAX_CONTAINER_CPUS = 2;
export const PODMAN_CONTAINER_PIDS_LIMIT = 512;
export const PODMAN_GLOBAL_MAX_CONTAINERS = 3;
export const PODMAN_GLOBAL_MEMORY_BUDGET_BYTES = 12 * 1024 ** 3;
export const PODMAN_GLOBAL_CPU_BUDGET = 6;
/** Keep clone/staging growth from consuming the last few host gigabytes. */
export const PODMAN_MIN_RUNTIME_FREE_BYTES = 4 * 1024 ** 3;

const LEASE_DIR_NAME = '.botmux-resource-leases';
const LOCK_DIR_NAME = '.lock';
const LOCK_WAIT_MS = 10;
const LOCK_TIMEOUT_MS = 5_000;

export interface PodmanResourceLease {
  readonly path: string;
  readonly memoryBytes: number;
  readonly cpus: number;
  release(): void;
}

interface ResourceLeaseRecord {
  readonly pid: number;
  readonly pidStartTime?: string;
  readonly sessionHash: string;
  readonly memoryBytes: number;
  readonly cpus: number;
  readonly createdAt: number;
}

export interface PodmanResourceAdmissionOptions {
  readonly maxContainers?: number;
  readonly memoryBudgetBytes?: number;
  readonly cpuBudget?: number;
  readonly now?: () => number;
  readonly pid?: number;
  readonly pidStartTime?: string;
}

export class PodmanResourceCapacityError extends Error {
  readonly code = 'podman_resource_capacity';

  constructor(message: string) {
    super(message);
    this.name = 'PodmanResourceCapacityError';
  }
}

export function assertPodmanRuntimeDiskHeadroom(
  runtimeRoot: string,
  minimumFreeBytes = PODMAN_MIN_RUNTIME_FREE_BYTES,
): void {
  try {
    const stats = statfsSync(resolve(runtimeRoot));
    const available = Number(stats.bavail) * Number(stats.bsize);
    if (!Number.isFinite(available) || available < minimumFreeBytes) {
      const availableGiB = Math.max(0, available / 1024 ** 3).toFixed(1);
      const minimumGiB = (minimumFreeBytes / 1024 ** 3).toFixed(1);
      throw new PodmanResourceCapacityError(
        `guest runtime disk is low (${availableGiB} GiB free; need at least ${minimumGiB} GiB)`,
      );
    }
  } catch (error) {
    if (error instanceof PodmanResourceCapacityError) throw error;
    throw new Error(`[podman] cannot inspect guest runtime disk: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function sleepSync(milliseconds: number): void {
  const shared = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(shared, 0, 0, milliseconds);
}

function processStartTime(pid: number): string | undefined {
  try {
    const body = readFileSync(`/proc/${pid}/stat`, 'utf8');
    const closeParen = body.lastIndexOf(')');
    if (closeParen < 0) return undefined;
    // Field 22 (starttime) is field 20 after the command name and its state.
    return body.slice(closeParen + 2).trim().split(/\s+/u)[19];
  } catch {
    return undefined;
  }
}

function processIsSame(pid: number, expectedStartTime?: string): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 1) return false;
  try {
    process.kill(pid, 0);
  } catch {
    return false;
  }
  if (!expectedStartTime) return true;
  return processStartTime(pid) === expectedStartTime;
}

function parseLease(path: string): ResourceLeaseRecord | undefined {
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
    const value = parsed as Record<string, unknown>;
    if (typeof value.pid !== 'number' || !Number.isSafeInteger(value.pid)
      || typeof value.sessionHash !== 'string'
      || typeof value.memoryBytes !== 'number' || !Number.isSafeInteger(value.memoryBytes)
      || typeof value.cpus !== 'number' || !Number.isFinite(value.cpus)
      || typeof value.createdAt !== 'number' || !Number.isFinite(value.createdAt)) {
      return undefined;
    }
    return {
      pid: value.pid,
      ...(typeof value.pidStartTime === 'string' ? { pidStartTime: value.pidStartTime } : {}),
      sessionHash: value.sessionHash,
      memoryBytes: value.memoryBytes,
      cpus: value.cpus,
      createdAt: value.createdAt,
    };
  } catch {
    return undefined;
  }
}

function ensureLeaseDirectory(runtimeRoot: string): string {
  const dir = join(resolve(runtimeRoot), LEASE_DIR_NAME);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

function withLock<T>(leaseDir: string, fn: () => T): T {
  const lockDir = join(leaseDir, LOCK_DIR_NAME);
  const started = Date.now();
  for (;;) {
    try {
      mkdirSync(lockDir, { mode: 0o700 });
      const ownerPath = join(lockDir, 'owner.json');
      writeFileSync(ownerPath, JSON.stringify({
        pid: process.pid,
        pidStartTime: processStartTime(process.pid),
      }), { mode: 0o600 });
      try {
        return fn();
      } finally {
        rmSync(lockDir, { recursive: true, force: true });
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      let stale = false;
      try {
        const owner = JSON.parse(readFileSync(join(lockDir, 'owner.json'), 'utf8')) as Record<string, unknown>;
        stale = typeof owner.pid !== 'number'
          || !processIsSame(owner.pid, typeof owner.pidStartTime === 'string' ? owner.pidStartTime : undefined);
      } catch {
        // A just-created lock may not have its owner file yet. Give it a few
        // retries before treating a damaged lock as stale.
        stale = Date.now() - started > LOCK_TIMEOUT_MS;
      }
      if (stale) {
        rmSync(lockDir, { recursive: true, force: true });
        continue;
      }
      if (Date.now() - started >= LOCK_TIMEOUT_MS) {
        throw new PodmanResourceCapacityError(
          'guest resource admission is busy; retry after the other launch finishes',
        );
      }
      sleepSync(LOCK_WAIT_MS);
    }
  }
}

function leaseFiles(leaseDir: string): string[] {
  return readdirSync(leaseDir)
    .filter(name => name.endsWith('.json') && name !== 'owner.json')
    .map(name => join(leaseDir, name));
}

function readLiveLeases(leaseDir: string): Array<{ path: string; record: ResourceLeaseRecord }> {
  const live: Array<{ path: string; record: ResourceLeaseRecord }> = [];
  for (const path of leaseFiles(leaseDir)) {
    const record = parseLease(path);
    if (!record || !processIsSame(record.pid, record.pidStartTime)) {
      try { unlinkSync(path); } catch { /* already reclaimed */ }
      continue;
    }
    live.push({ path, record });
  }
  return live;
}

/**
 * Reserve one guest's hard resource budget. The returned lease must be
 * released when the container is stopped; dead workers are reclaimed on the
 * next admission attempt.
 */
export function acquirePodmanResourceLease(
  runtimeRoot: string,
  sessionHash: string,
  memoryBytes: number,
  cpus: number,
  options: PodmanResourceAdmissionOptions = {},
): PodmanResourceLease {
  if (!/^[0-9a-f]{24}$/u.test(sessionHash)) {
    throw new Error('[podman] resource session hash is invalid');
  }
  if (!Number.isSafeInteger(memoryBytes) || memoryBytes <= 0 || memoryBytes > PODMAN_MAX_CONTAINER_MEMORY_BYTES) {
    throw new Error(`[podman] guest memory must be at most ${PODMAN_MAX_CONTAINER_MEMORY_BYTES / 1024 ** 3} GiB`);
  }
  if (!Number.isFinite(cpus) || cpus <= 0 || cpus > PODMAN_MAX_CONTAINER_CPUS) {
    throw new Error(`[podman] guest CPU must be at most ${PODMAN_MAX_CONTAINER_CPUS}`);
  }

  const maxContainers = options.maxContainers ?? PODMAN_GLOBAL_MAX_CONTAINERS;
  const memoryBudgetBytes = options.memoryBudgetBytes ?? PODMAN_GLOBAL_MEMORY_BUDGET_BYTES;
  const cpuBudget = options.cpuBudget ?? PODMAN_GLOBAL_CPU_BUDGET;
  const leaseDir = ensureLeaseDirectory(runtimeRoot);
  const leasePath = join(leaseDir, `${sessionHash}.json`);
  const pid = options.pid ?? process.pid;
  const pidStartTime = options.pidStartTime ?? processStartTime(pid);
  const now = options.now ?? Date.now;

  return withLock(leaseDir, () => {
    const live = readLiveLeases(leaseDir);
    if (live.some(item => item.record.sessionHash === sessionHash)) {
      throw new PodmanResourceCapacityError(
        `guest session ${sessionHash} already owns a resource lease`,
      );
    }
    const usedMemory = live.reduce((sum, item) => sum + item.record.memoryBytes, 0);
    const usedCpus = live.reduce((sum, item) => sum + item.record.cpus, 0);
    if (live.length >= maxContainers || usedMemory + memoryBytes > memoryBudgetBytes || usedCpus + cpus > cpuBudget) {
      const usedGiB = (usedMemory / 1024 ** 3).toFixed(1);
      const maxGiB = (memoryBudgetBytes / 1024 ** 3).toFixed(1);
      throw new PodmanResourceCapacityError(
        `guest capacity reached (${live.length}/${maxContainers} containers, ${usedGiB}/${maxGiB} GiB memory, ${usedCpus}/${cpuBudget} CPUs); suspend or wait for another guest`,
      );
    }
    const record: ResourceLeaseRecord = {
      pid,
      ...(pidStartTime ? { pidStartTime } : {}),
      sessionHash,
      memoryBytes,
      cpus,
      createdAt: now(),
    };
    writeFileSync(leasePath, `${JSON.stringify(record)}\n`, { mode: 0o600, flag: 'wx' });
    let released = false;
    return {
      path: leasePath,
      memoryBytes,
      cpus,
      release(): void {
        if (released) return;
        released = true;
        try {
          withLock(leaseDir, () => {
            const current = parseLease(leasePath);
            if (current?.pid === pid && current.sessionHash === sessionHash) {
              try { unlinkSync(leasePath); } catch { /* already gone */ }
            }
          });
        } catch {
          // A dead/exiting worker cannot report cleanup failure. The next
          // admission reclaims a lease whose pid is no longer alive.
        }
      },
    };
  });
}

export function podmanMemoryBytes(raw: string): number {
  const match = /^([0-9]+)([kmgt]i?|)$/iu.exec(raw.trim());
  if (!match) throw new Error(`invalid Podman memory quantity: ${raw}`);
  const amount = Number(match[1]);
  const suffix = (match[2] ?? '').toLowerCase();
  const units: Record<string, number> = {
    '': 1,
    k: 1000,
    ki: 1024,
    m: 1000 ** 2,
    mi: 1024 ** 2,
    g: 1000 ** 3,
    gi: 1024 ** 3,
    t: 1000 ** 4,
    ti: 1024 ** 4,
  };
  const bytes = amount * (units[suffix] ?? 0);
  if (!Number.isSafeInteger(bytes) || bytes <= 0) throw new Error(`invalid Podman memory quantity: ${raw}`);
  return bytes;
}
