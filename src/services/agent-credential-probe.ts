/**
 * Short-lived, rootless provider probe for API credentials.
 *
 * The dashboard never sends a key from the host process directly to a
 * provider.  It passes the key through a one-shot Podman container's process
 * environment, while the fixed image entrypoint selects the bot's harness.
 * No host path is mounted and the container has no host network, gateway
 * alias, or published port.
 */
import { randomBytes } from 'node:crypto';
import { spawn, type ChildProcess } from 'node:child_process';
import { fixedBotCliId, type PodmanCliId, type PodmanExecutionConfig } from '../execution/podman-execution.js';

export const AGENT_CREDENTIAL_PROBE_TIMEOUT_MS = 20_000;
const MAX_PROBE_TIMEOUT_MS = 60_000;
const PROBE_MEMORY = '512m';
const PROBE_CPUS = '1';
const PROBE_PROMPT = 'Reply with exactly OK and do not use tools.';

export class AgentCredentialProbeError extends Error {
  constructor() {
    super('credential_probe_failed');
    this.name = 'AgentCredentialProbeError';
  }
}

export interface AgentCredentialProbeInput {
  readonly cliId: string;
  readonly image: string;
  readonly apiKey: string;
  readonly baseUrl: string;
  readonly model: string;
}

export interface AgentCredentialProbeCommandOptions {
  readonly cwd?: string;
  readonly env?: Readonly<Record<string, string>>;
  readonly timeoutMs: number;
}

export interface AgentCredentialProbeCommandResult {
  readonly status: number | null;
  readonly timedOut?: boolean;
}

export type AgentCredentialProbeCommand = (
  command: string,
  args: readonly string[],
  options: AgentCredentialProbeCommandOptions,
) => Promise<AgentCredentialProbeCommandResult>;

export type AgentCredentialProbeCleanup = (
  command: string,
  containerName: string,
  options: AgentCredentialProbeCommandOptions,
) => Promise<void>;

export interface AgentCredentialProbePlan {
  readonly command: 'podman';
  readonly args: readonly string[];
  readonly env: Readonly<Record<string, string>>;
  readonly containerName: string;
  readonly cliId: PodmanCliId;
}

function safeProbeText(value: unknown, name: string, maxLength: number): string {
  if (typeof value !== 'string' || value.trim() === '' || value.length > maxLength
    || /[\u0000\r\n]/u.test(value)) {
    throw new AgentCredentialProbeError();
  }
  return value.trim();
}

function safeProbeInput(input: AgentCredentialProbeInput): {
  readonly cliId: PodmanCliId;
  readonly image: string;
  readonly apiKey: string;
  readonly baseUrl: string;
  readonly model: string;
} {
  let cliId: PodmanCliId;
  try {
    cliId = fixedBotCliId({ cliId: input.cliId });
  } catch {
    throw new AgentCredentialProbeError();
  }
  const image = safeProbeText(input.image, 'image', 512);
  const apiKey = safeProbeText(input.apiKey, 'apiKey', 4096);
  const baseUrl = safeProbeText(input.baseUrl, 'baseUrl', 2048);
  const model = safeProbeText(input.model, 'model', 256);
  return { cliId, image, apiKey, baseUrl, model };
}

function probeContainerName(): string {
  return `botmux-credential-probe-${randomBytes(12).toString('hex')}`;
}

/** Build the exact one-shot command. The secret appears only in `env`, never argv. */
export function buildAgentCredentialProbePlan(
  input: AgentCredentialProbeInput,
  hostUid = process.getuid?.() ?? 0,
  hostGid = process.getgid?.() ?? 0,
): AgentCredentialProbePlan {
  const safe = safeProbeInput(input);
  if (!Number.isSafeInteger(hostUid) || hostUid <= 0 || !Number.isSafeInteger(hostGid) || hostGid < 0) {
    throw new AgentCredentialProbeError();
  }
  const containerName = probeContainerName();
  const commonArgs = [
    'run', '--rm', '--userns=keep-id', `--user=${hostUid}:${hostGid}`,
    // Pasta is rootless and has no gateway mapping or published ports here.
    '--network=pasta:--no-map-gw',
    '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=128',
    `--memory=${PROBE_MEMORY}`, `--cpus=${PROBE_CPUS}`,
    '--tmpfs=/tmp:rw,nosuid,nodev', `--name=${containerName}`,
    '--env=AGENT_API_KEY', '--env=AGENT_BASE_URL', '--env=AGENT_MODEL',
    `--env=BOTMUX_HARNESS=${safe.cliId}`,
    '--env=BOTMUX_CREDENTIAL_KIND=api', '--env=BOTMUX_CREDENTIAL_VERSION=probe',
    '--env=AGENT_PROVIDER=openai-compatible',
    '--env=AGENT_WORKSPACE=/tmp/botmux-credential-probe-workspace',
    '--env=AGENT_SESSION_HOME=/tmp/botmux-credential-probe-home',
    '--env=HOME=/tmp/botmux-credential-probe-home',
    safe.image, '--',
  ];

  // The image entrypoint owns the installed harness. Each invocation below is
  // non-interactive and bounded to one request. Codex gets the real custom
  // provider TOML contract through -c; the other lanes consume the fixed
  // provider aliases materialized by the entrypoint.
  const cliArgs: string[] = (() => {
    switch (safe.cliId) {
      case 'codex':
        return [
          'exec', '--ephemeral', '--json', '--skip-git-repo-check',
          '-c', 'model_provider="botmux_api"',
          '-c', `model=${JSON.stringify(safe.model)}`,
          '-c', 'model_providers.botmux_api.name="botmux_api"',
          '-c', `model_providers.botmux_api.base_url=${JSON.stringify(safe.baseUrl)}`,
          '-c', 'model_providers.botmux_api.env_key="OPENAI_API_KEY"',
          '-c', 'model_providers.botmux_api.wire_api="responses"',
          '-m', safe.model,
          PROBE_PROMPT,
        ];
      case 'claude-code':
        return [
          '--print', '--bare', '--no-session-persistence', '--max-turns', '1',
          '--output-format', 'text', '--model', safe.model, PROBE_PROMPT,
        ];
      case 'pi':
        return [
          '--print', '--no-session', '--no-tools', '--no-extensions', '--no-skills',
          '--provider', 'openai', '--model', safe.model, PROBE_PROMPT,
        ];
      case 'opencode':
        return ['run', '--pure', '--format', 'json', '--model', safe.model, PROBE_PROMPT];
    }
  })();

  return {
    command: 'podman',
    args: [...commonArgs, ...cliArgs],
    env: {
      PATH: process.env.PATH ?? '/usr/bin:/bin',
      HOME: process.env.HOME ?? '/tmp',
      XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR ?? '',
      TMPDIR: process.env.TMPDIR ?? '/tmp',
      LANG: process.env.LANG ?? 'C.UTF-8',
      LC_ALL: process.env.LC_ALL ?? 'C.UTF-8',
      // This is intentionally the only value that is not represented by a
      // fixed command argument. The child receives it through --env=... above.
      AGENT_API_KEY: safe.apiKey,
      AGENT_BASE_URL: safe.baseUrl,
      AGENT_MODEL: safe.model,
    },
    containerName,
    cliId: safe.cliId,
  };
}

function defaultProbeCommand(
  command: string,
  args: readonly string[],
  options: AgentCredentialProbeCommandOptions,
): Promise<AgentCredentialProbeCommandResult> {
  return new Promise(resolvePromise => {
    let child: ChildProcess;
    try {
      child = spawn(command, [...args], {
        cwd: options.cwd,
        env: options.env ? { ...options.env } : undefined,
        shell: false,
        stdio: ['ignore', 'ignore', 'ignore'],
      });
    } catch {
      resolvePromise({ status: null });
      return;
    }
    let settled = false;
    let timedOut = false;
    const finish = (status: number | null): void => {
      if (settled) return;
      settled = true;
      resolvePromise({ status, ...(timedOut ? { timedOut: true } : {}) });
    };
    const timer = setTimeout(() => {
      timedOut = true;
      try { child.kill('SIGKILL'); } catch { /* process may already have exited */ }
      finish(null);
    }, options.timeoutMs);
    timer.unref?.();
    child.once('error', () => { clearTimeout(timer); finish(null); });
    child.once('close', status => { clearTimeout(timer); finish(status); });
  });
}

function defaultProbeCleanup(
  command: string,
  containerName: string,
  options: AgentCredentialProbeCommandOptions,
): Promise<void> {
  return new Promise(resolvePromise => {
    let child: ChildProcess;
    try {
      child = spawn(command, ['rm', '--force', '--ignore', containerName], {
        cwd: options.cwd,
        env: options.env ? { ...options.env } : undefined,
        shell: false,
        stdio: 'ignore',
      });
    } catch {
      resolvePromise();
      return;
    }
    child.once('close', () => resolvePromise());
    child.once('error', () => resolvePromise());
  });
}

/** Probe one API credential, failing closed with a sanitized error. */
export async function probeAgentApiCredential(
  input: AgentCredentialProbeInput,
  options: {
    readonly hostUid?: number;
    readonly hostGid?: number;
    readonly timeoutMs?: number;
    readonly commandRunner?: AgentCredentialProbeCommand;
    readonly cleanup?: AgentCredentialProbeCleanup;
  } = {},
): Promise<void> {
  const plan = buildAgentCredentialProbePlan(input, options.hostUid, options.hostGid);
  const timeoutMs = Math.min(MAX_PROBE_TIMEOUT_MS, Math.max(1_000, Math.trunc(options.timeoutMs ?? AGENT_CREDENTIAL_PROBE_TIMEOUT_MS)));
  const commandRunner = options.commandRunner ?? defaultProbeCommand;
  const cleanup = options.cleanup ?? defaultProbeCleanup;
  const cleanupEnv = Object.fromEntries(
    Object.entries(plan.env).filter(([key]) => key !== 'AGENT_API_KEY'),
  );
  let failed = false;
  try {
    let result: AgentCredentialProbeCommandResult;
    try {
      result = await commandRunner(plan.command, plan.args, {
        cwd: '/tmp', env: plan.env, timeoutMs,
      });
    } catch {
      failed = true;
      throw new AgentCredentialProbeError();
    }
    if (result.status !== 0 || result.timedOut) {
      failed = true;
      throw new AgentCredentialProbeError();
    }
  } finally {
    try {
      await cleanup(plan.command, plan.containerName, {
        cwd: '/tmp', env: cleanupEnv, timeoutMs: Math.min(timeoutMs, 5_000),
      });
    } catch {
      failed = true;
    }
  }
  if (failed) throw new AgentCredentialProbeError();
}

/** Production convenience for dashboard wiring. */
export async function probePodmanApiCredential(input: {
  readonly execution: PodmanExecutionConfig;
  readonly cliId: string;
  readonly apiKey: string;
  readonly baseUrl: string;
  readonly model: string;
}): Promise<void> {
  await probeAgentApiCredential({
    cliId: input.cliId,
    image: input.execution.image,
    apiKey: input.apiKey,
    baseUrl: input.baseUrl,
    model: input.model,
  });
}
