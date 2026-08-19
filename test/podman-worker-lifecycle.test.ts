import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const workerSource = readFileSync(new URL('../src/worker.ts', import.meta.url), 'utf8');

describe('Podman worker exit cleanup', () => {
  it('awaits the provider stop fence for signal, disconnect, and crash paths', () => {
    const helperStart = workerSource.indexOf('function requestWorkerExit(');
    const helperEnd = workerSource.indexOf("process.on('SIGTERM'", helperStart);
    const helper = workerSource.slice(helperStart, helperEnd);
    expect(helper).toContain('await waitForPodmanStop()');
    expect(helper).toContain('stopPreparedPodmanExecution()');

    const signalEnd = workerSource.indexOf('// Watchdog:', helperEnd);
    const signals = workerSource.slice(helperEnd, signalEnd);
    expect(signals).toContain("process.on('SIGTERM', () => { requestWorkerExit(0); });");
    expect(signals).toContain("process.on('SIGINT', () => { requestWorkerExit(0); });");
    expect(signals).toContain("process.on('disconnect', () => { log('Daemon disconnected'); requestWorkerExit(0); });");

    const crashStart = workerSource.indexOf("process.on('uncaughtException'");
    const crash = workerSource.slice(crashStart);
    expect(crash).toContain('requestWorkerExit(1, { crash: true, skipCliKill: true });');
    expect(crash).toContain("process.on('unhandledRejection'");
  });

  it('keeps a synchronous stop guard in the non-awaitable exit hook', () => {
    const start = workerSource.indexOf("process.on('exit'");
    const end = workerSource.indexOf("process.on('uncaughtException'", start);
    expect(workerSource.slice(start, end)).toContain('stopSyncBestEffort');
  });

  it('awaits Podman stop before explicit close, transfer, and Riff shutdown exits', () => {
    for (const marker of ["case 'close_commit':", "case 'detach_for_transfer':", "case 'riff_shutdown_commit':"]) {
      const start = workerSource.indexOf(marker);
      const end = workerSource.indexOf('process.exit(0)', start);
      expect(start).toBeGreaterThanOrEqual(0);
      expect(end).toBeGreaterThan(start);
      expect(workerSource.slice(start, end)).toContain('await waitForPodmanStop()');
    }
    const suspendStart = workerSource.indexOf("case 'suspend':");
    const suspendEnd = workerSource.indexOf('process.exit(0)', suspendStart);
    expect(workerSource.slice(suspendStart, suspendEnd)).toContain('await waitForPodmanStop()');
  });
});
