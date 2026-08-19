/** Per-principal Codex ChatGPT device-auth coordination. */
import { randomUUID } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, rmdirSync, unlinkSync, watch, writeFileSync, type FSWatcher } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { spawn, type ChildProcess } from 'node:child_process';
import { AgentPrincipalLookupError, type AgentPrincipalKey, type AgentPrincipalRepository, type AgentCredentialMetadata, type AgentCodexLoginTaskRecord, type AgentPrincipalRow } from './agent-principal-store.js';
import { redactCredentialText } from './agent-principal-crypto.js';

export const CODEX_DEVICE_AUTH_LEASE_MS = 5 * 60_000;
export const CODEX_STATUS_PROBE_TIMEOUT_MS = 15_000;

/** A refresh watcher is meaningful only for the ChatGPT auth-file flow. */
export function shouldStartCodexAuthRefreshWatcher(input: {
  readonly cliId: string;
  readonly credentialKind?: string;
}): boolean {
  return input.cliId === 'codex' && input.credentialKind === 'codex_chatgpt';
}

export interface CodexDeviceAuthChallenge {
  readonly verificationUri: string;
  readonly userCode: string;
}

export interface CodexDeviceAuthRunner {
  startDeviceAuth(input: { readonly authPath: string; readonly timeoutMs: number }): Promise<CodexDeviceAuthChallenge>;
  logout(input: { readonly authPath: string }): Promise<void>;
  status(input: { readonly authPath: string }): Promise<{ readonly loggedIn: boolean }>;
  /** Stop a long-lived device-auth process after completion/expiry. */
  dispose?(input: { readonly authPath: string }): Promise<void> | void;
}

export interface CodexLoginTaskView {
  readonly taskId: string;
  readonly status: 'pending' | 'ready' | 'failed' | 'logged_out' | 'expired';
  readonly verificationUri?: string;
  readonly userCode?: string;
  readonly expiresAt: string;
}

export interface PodmanCodexDeviceAuthRunnerOptions {
  /** Immutable digest-pinned image used only for the login helper. */
  readonly image: string;
  /** Dedicated host root containing temporary auth dirs, never ~/.codex. */
  readonly authRoot: string;
  readonly hostUid?: number;
  readonly hostGid?: number;
  readonly command?: string;
  /** Test seam; production defaults to the bounded status probe timeout. */
  readonly statusTimeoutMs?: number;
}

interface PodmanOneShotResult {
  readonly status: number | null;
  readonly timedOut: boolean;
}

const CODEX_IMAGE_RE = /^[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}$/u;

function assertAuthUnderRoot(path: string, root: string): string {
  const authPath = safeAuthPath(path);
  const authRoot = resolve(root);
  if (authPath !== join(authRoot, 'auth.json') && !authPath.startsWith(`${authRoot}/`)) {
    throw new Error('Codex device auth path is outside its dedicated credential root');
  }
  return authPath;
}

function parseDeviceChallenge(output: string): CodexDeviceAuthChallenge | undefined {
  const uri = output.match(/https:\/\/[^\s"'<>]+/iu)?.[0]?.replace(/[),.;]+$/u, '');
  if (!uri) return undefined;
  const codeMatch = output.match(/(?:device\s+)?(?:code|code\s+is)\s*[:=]?\s*([A-Z0-9][A-Z0-9-]{5,})/iu)
    ?? output.match(/\b([A-Z0-9]{4,}(?:-[A-Z0-9]{3,})+)\b/u);
  const userCode = codeMatch?.[1]?.toUpperCase();
  return userCode ? { verificationUri: uri, userCode } : undefined;
}

function authJsonIsLoggedIn(path: string): boolean {
  let parsed: unknown;
  try { parsed = JSON.parse(readFileSync(path, 'utf8')); } catch { return false; }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return false;
  const text = JSON.stringify(parsed);
  // A `tokens` object by itself is not proof of a completed login.  Require a
  // concrete non-empty token field so a truncated `{}` cannot overwrite a
  // previously valid credential through the refresh watcher.
  return /"(?:access|refresh|id)[_-]?token"\s*:\s*"(?:[^"\\]|\\.)+"/iu.test(text);
}

function runPodmanOneShot(input: {
  readonly command: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly env: Readonly<Record<string, string>>;
  readonly timeoutMs: number;
}): Promise<PodmanOneShotResult> {
  return new Promise(resolveResult => {
    let child: ChildProcess;
    try {
      child = spawn(input.command, [...input.args], {
        cwd: input.cwd,
        env: { ...input.env },
        shell: false,
        // Status output can contain account/token details. It is deliberately
        // discarded at the process boundary rather than parsed or logged.
        stdio: 'ignore',
      });
    } catch {
      resolveResult({ status: null, timedOut: false });
      return;
    }
    let settled = false;
    let timedOut = false;
    const finish = (status: number | null): void => {
      if (settled) return;
      settled = true;
      resolveResult({ status, timedOut });
    };
    const timer = setTimeout(() => {
      timedOut = true;
      try { child.kill('SIGKILL'); } catch { /* process may already have exited */ }
      // Podman should emit close after SIGKILL. The bounded fallback prevents
      // a broken runtime from holding the login request forever.
      const fallback = setTimeout(() => finish(null), 1_000);
      fallback.unref?.();
    }, Math.max(1_000, input.timeoutMs));
    timer.unref?.();
    child.once('error', () => { clearTimeout(timer); finish(null); });
    child.once('close', status => { clearTimeout(timer); finish(status); });
  });
}

/**
 * Real device-auth runner. It launches only the pinned image and mounts one
 * task-local auth directory. The host's ~/.codex is never read or mounted.
 */
export class PodmanCodexDeviceAuthRunner implements CodexDeviceAuthRunner {
  private readonly children = new Map<string, ChildProcess>();
  private readonly image: string;
  private readonly authRoot: string;
  private readonly uid: number;
  private readonly gid: number;
  private readonly command: string;
  private readonly statusTimeoutMs: number;

  constructor(options: PodmanCodexDeviceAuthRunnerOptions) {
    if (!CODEX_IMAGE_RE.test(options.image)) throw new Error('Codex device auth image must be digest-pinned');
    this.image = options.image;
    this.authRoot = resolve(options.authRoot);
    this.uid = options.hostUid ?? process.getuid?.() ?? 0;
    this.gid = options.hostGid ?? process.getgid?.() ?? 0;
    if (!Number.isSafeInteger(this.uid) || this.uid <= 0 || !Number.isSafeInteger(this.gid) || this.gid < 0) {
      throw new Error('Codex device auth runner requires a non-root host user');
    }
    this.command = options.command ?? 'podman';
    this.statusTimeoutMs = Math.max(1_000, Math.trunc(options.statusTimeoutMs ?? CODEX_STATUS_PROBE_TIMEOUT_MS));
  }

  private podmanEnv(): Readonly<Record<string, string>> {
    return {
      PATH: process.env.PATH ?? '/usr/bin:/bin',
      HOME: '/tmp',
      LANG: process.env.LANG ?? 'C.UTF-8',
      LC_ALL: process.env.LC_ALL ?? 'C.UTF-8',
    };
  }

  private async cleanupContainer(containerName: string): Promise<void> {
    await runPodmanOneShot({
      command: this.command,
      args: ['rm', '--force', '--ignore', containerName],
      cwd: this.authRoot,
      env: this.podmanEnv(),
      timeoutMs: 5_000,
    });
  }

  private args(authPath: string, command: readonly string[], mode: 'ro' | 'rw', containerName?: string): string[] {
    const safe = assertAuthUnderRoot(authPath, this.authRoot);
    const authDir = dirname(safe);
    mkdirSync(authDir, { recursive: true, mode: 0o700 });
    chmodSync(authDir, 0o700);
    return [
      'run', '--rm', '--entrypoint=codex', '--userns=keep-id', `--user=${this.uid}:${this.gid}`,
      '--network=pasta:--no-map-gw', '--cap-drop=ALL', '--security-opt=no-new-privileges',
      '--pids-limit=128', '--tmpfs=/tmp:rw,nosuid,nodev',
      `--mount=type=bind,src=${authDir},dst=/home/dev/.codex,${mode}`,
      ...(containerName ? [`--name=${containerName}`] : []),
      '--env=HOME=/home/dev', '--env=CODEX_HOME=/home/dev/.codex',
      this.image, ...command,
    ];
  }

  async startDeviceAuth(input: { readonly authPath: string; readonly timeoutMs: number }): Promise<CodexDeviceAuthChallenge> {
    const authPath = assertAuthUnderRoot(input.authPath, this.authRoot);
    await this.dispose({ authPath });
    const child = spawn(this.command, this.args(authPath, ['login', '--device-auth'], 'rw'), {
      cwd: this.authRoot,
      env: {
        PATH: process.env.PATH ?? '/usr/bin:/bin',
        HOME: '/tmp',
        LANG: process.env.LANG ?? 'C.UTF-8',
        LC_ALL: process.env.LC_ALL ?? 'C.UTF-8',
      },
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    this.children.set(authPath, child);
    return await new Promise<CodexDeviceAuthChallenge>((resolveChallenge, reject) => {
      let output = '';
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        void this.dispose({ authPath });
        reject(new Error('Codex device auth challenge timed out'));
      }, Math.max(1_000, input.timeoutMs));
      timer.unref?.();
      const consume = (chunk: Buffer): void => {
        if (settled) return;
        output += chunk.toString('utf8');
        const challenge = parseDeviceChallenge(output);
        if (challenge) {
          settled = true;
          clearTimeout(timer);
          resolveChallenge(challenge);
        }
      };
      child.stdout?.on('data', consume);
      child.stderr?.on('data', consume);
      child.once('error', error => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.children.delete(authPath);
        reject(new Error(redactCredentialText(error)));
      });
      child.once('close', code => {
        this.children.delete(authPath);
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(new Error(`Codex device auth exited before challenge (status ${String(code ?? 1)})`));
      });
    });
  }

  async status(input: { readonly authPath: string }): Promise<{ readonly loggedIn: boolean }> {
    const authPath = assertAuthUnderRoot(input.authPath, this.authRoot);
    let stat;
    try { stat = lstatSync(authPath); } catch { return { loggedIn: false }; }
    if (!stat.isFile() || stat.isSymbolicLink() || !authJsonIsLoggedIn(authPath)) return { loggedIn: false };
    const containerName = `botmux-codex-status-${randomUUID().replace(/-/gu, '')}`;
    const args = this.args(authPath, ['login', 'status'], 'ro', containerName);
    try {
      const result = await runPodmanOneShot({
        command: this.command,
        args,
        cwd: this.authRoot,
        env: this.podmanEnv(),
        timeoutMs: this.statusTimeoutMs,
      });
      if (result.timedOut || result.status === null) throw new Error('Codex login status probe failed');
      return { loggedIn: result.status === 0 };
    } finally {
      await this.cleanupContainer(containerName);
    }
  }

  async logout(input: { readonly authPath: string }): Promise<void> {
    const authPath = assertAuthUnderRoot(input.authPath, this.authRoot);
    await this.dispose({ authPath });
    // `codex login --device-auth` owns the temporary auth file. Removing this
    // task-local material is the logout operation; the encrypted DB copy is
    // removed by CodexDeviceLoginService separately.
    removeCodexAuthMaterial(authPath);
  }

  async dispose(input: { readonly authPath: string }): Promise<void> {
    const authPath = assertAuthUnderRoot(input.authPath, this.authRoot);
    const child = this.children.get(authPath);
    if (!child) return;
    this.children.delete(authPath);
    if (!child.killed) child.kill('SIGTERM');
    await new Promise<void>(resolvePromise => {
      const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* */ } resolvePromise(); }, 2_000);
      timer.unref?.();
      child.once('close', () => { clearTimeout(timer); resolvePromise(); });
    });
  }
}

function safeKey(key: AgentPrincipalKey): AgentPrincipalKey {
  if (!key.larkAppId || !key.openId || /[\u0000\r\n]/u.test(key.larkAppId + key.openId)) throw new Error('invalid app-scoped principal');
  return key;
}

function safeAuthPath(path: string): string {
  const resolved = resolve(path);
  for (const forbiddenRoot of [join(homedir(), '.codex'), join(homedir(), '.claude')]) {
    if (resolved === forbiddenRoot || resolved.startsWith(`${forbiddenRoot}/`)) {
      throw new Error('Codex auth path may not point at the host CLI credential directory');
    }
  }
  let cursor = '/';
  for (const segment of resolved.split('/').filter(Boolean)) {
    cursor = join(cursor, segment);
    let component;
    try { component = lstatSync(cursor); } catch { continue; }
    if (component.isSymbolicLink()) throw new Error('Codex auth path may not traverse symlinks');
  }
  const stat = existsSync(resolved) ? lstatSync(resolved) : undefined;
  if (stat && (!stat.isFile() || stat.isSymbolicLink())) throw new Error('Codex auth path is not a regular file');
  return resolved;
}

/** Write one principal's decrypted auth material to an isolated runtime file.
 * The caller must discard `authJson` after this synchronous atomic write. */
export function writeCodexAuthJson(input: { readonly authPath: string; readonly authJson: string }): void {
  let parsed: unknown;
  try { parsed = JSON.parse(input.authJson); } catch { throw new Error('stored Codex auth credential is not valid JSON'); }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('stored Codex auth credential must be a JSON object');
  }
  const path = safeAuthPath(input.authPath);
  const parent = dirname(path);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  chmodSync(parent, 0o700);
  safeAuthPath(path);
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporary, JSON.stringify(parsed) + '\n', { encoding: 'utf8', mode: 0o600 });
    chmodSync(temporary, 0o600);
    // Re-check the destination immediately before replacement: a symlink swap
    // in a runtime root must fail closed instead of redirecting the auth write.
    safeAuthPath(path);
    renameSync(temporary, path);
  } finally {
    try { unlinkIfPresent(temporary); } catch { /* best-effort cleanup */ }
  }
}

function unlinkIfPresent(path: string): void {
  try {
    unlinkSync(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

/** Remove a short-lived login credential without recursively trusting a path. */
function removeCodexAuthMaterial(path: string): void {
  const safe = safeAuthPath(path);
  try {
    unlinkIfPresent(safe);
  } catch {
    // Login cleanup is best effort, but never follow a symlink or remove a
    // directory. The safeAuthPath check above makes a failed cleanup visible
    // only through the caller's normal error path, not through secret text.
  }
  // The task auth directory is short-lived material too. Remove only the
  // empty, non-symlink leaf after unlinking auth.json; rmdir never follows a
  // symlink if an attacker races the lstat between these operations.
  const parent = dirname(safe);
  try {
    const stat = lstatSync(parent);
    if (stat.isDirectory() && !stat.isSymbolicLink()) rmdirSync(parent);
  } catch {
    // Best effort: a non-empty or concurrently removed directory is harmless.
  }
}

async function disposeRunner(runner: CodexDeviceAuthRunner, authPath: string): Promise<void> {
  try { await runner.dispose?.({ authPath }); } catch { /* best-effort process cleanup */ }
}

export async function materializeCodexAuthJson(input: {
  readonly repository: Pick<AgentPrincipalRepository, 'readSecret'>;
  readonly key: AgentPrincipalKey;
  readonly expectedVersion?: number;
  readonly authPath: string;
}): Promise<AgentCredentialMetadata> {
  const key = safeKey(input.key);
  const result = await input.repository.readSecret(key, input.expectedVersion);
  writeCodexAuthJson({ authPath: input.authPath, authJson: result.secret });
  return result.metadata;
}

type ActiveCodexLoginTask = {
  readonly taskId: string;
  readonly expiresAt: number;
  readonly key: AgentPrincipalKey;
  timer?: ReturnType<typeof setTimeout>;
};

export class CodexDeviceLoginService {
  private readonly active = new Map<string, ActiveCodexLoginTask>();
  private readonly leaseMs: number;

  constructor(private readonly input: {
    readonly repository: Pick<AgentPrincipalRepository, 'beginCodexLoginTask' | 'updateCodexLoginTask' | 'putCredential' | 'deleteCredential'> & {
      readonly getCodexLoginTask?: (key: AgentPrincipalKey) => Promise<AgentCodexLoginTaskRecord | undefined>;
      readonly getPrincipal?: (key: AgentPrincipalKey) => Promise<AgentPrincipalRow | undefined>;
    };
    readonly authPathFor: (key: AgentPrincipalKey, taskId: string) => string;
    readonly runner: CodexDeviceAuthRunner;
    readonly stopSessionsForPrincipal?: (key: AgentPrincipalKey) => Promise<void> | void;
    /** Canonical per-principal cache used by live Podman sessions. */
    readonly canonicalAuthPathFor?: (key: AgentPrincipalKey) => string;
    readonly notifyDeviceChallenge?: (key: AgentPrincipalKey, challenge: CodexDeviceAuthChallenge) => Promise<void> | void;
    readonly now?: () => number;
    /** Short lease seam for deterministic tests; production remains 5 min. */
    readonly leaseMs?: number;
  }) {
    this.leaseMs = Math.max(1, Math.trunc(input.leaseMs ?? CODEX_DEVICE_AUTH_LEASE_MS));
  }

  private now(): number { return this.input.now?.() ?? Date.now(); }

  private identity(key: AgentPrincipalKey): string {
    return `${key.larkAppId}\0${key.openId}`;
  }

  private clearActive(identity: string): ActiveCodexLoginTask | undefined {
    const active = this.active.get(identity);
    if (active?.timer) clearTimeout(active.timer);
    if (active) this.active.delete(identity);
    return active;
  }

  private clearActiveExact(identity: string, taskId: string): void {
    const active = this.active.get(identity);
    if (active?.taskId === taskId) this.clearActive(identity);
  }

  private scheduleExpiry(identity: string, active: ActiveCodexLoginTask): void {
    const delay = Math.max(0, active.expiresAt - this.now());
    const timer = setTimeout(() => {
      void this.expireActive(identity, active.taskId, active.expiresAt);
    }, delay);
    timer.unref?.();
    active.timer = timer;
  }

  /** Expire only the exact lease generation that scheduled this callback. */
  private async expireActive(identity: string, taskId: string, expiresAt: number): Promise<void> {
    const active = this.active.get(identity);
    if (!active || active.taskId !== taskId || active.expiresAt !== expiresAt) return;
    if (this.now() < expiresAt) {
      if (active.timer) clearTimeout(active.timer);
      this.scheduleExpiry(identity, active);
      return;
    }
    this.clearActive(identity);
    await this.input.repository.updateCodexLoginTask(taskId, {
      status: 'expired', errorCode: 'device_auth_expired',
    }).catch(() => undefined);
    const authPath = this.input.authPathFor(active.key, taskId);
    await disposeRunner(this.input.runner, authPath);
    try { removeCodexAuthMaterial(authPath); } catch { /* fail closed; expiry already fenced the task */ }
  }

  private async reapExpiredStoredTask(key: AgentPrincipalKey, task: AgentCodexLoginTaskRecord | undefined, now: number): Promise<boolean> {
    if (!task || task.status !== 'pending' || Date.parse(task.leaseExpiresAt) > now) return false;
    await this.input.repository.updateCodexLoginTask(task.taskId, {
      status: 'expired', errorCode: 'device_auth_expired',
    }).catch(() => undefined);
    const authPath = this.input.authPathFor(key, task.taskId);
    await disposeRunner(this.input.runner, authPath);
    try { removeCodexAuthMaterial(authPath); } catch { /* best effort, never follow a symlink */ }
    this.clearActive(this.identity(key));
    return true;
  }

  private async requireEnabled(key: AgentPrincipalKey): Promise<void> {
    const principal = await this.input.repository.getPrincipal?.(key);
    // Production repositories always expose getPrincipal. Optionality keeps
    // the narrow runner seam usable by deterministic unit fakes.
    if (principal && !principal.enabled) throw new AgentPrincipalLookupError('disabled', 'principal is disabled');
    if (this.input.repository.getPrincipal && !principal) throw new AgentPrincipalLookupError('not_found', 'principal is not registered');
  }

  async begin(keyInput: AgentPrincipalKey, context: { readonly chatType: 'p2p' | 'group'; readonly botCliId: string }): Promise<CodexLoginTaskView> {
    const key = safeKey(keyInput);
    await this.requireEnabled(key);
    if (context.chatType !== 'p2p') throw new Error('Codex device auth must be started from the principal private chat');
    if (context.botCliId !== 'codex') throw new Error('Codex device auth is available only for a Codex bot');
    const now = this.now();
    const identity = this.identity(key);
    const prior = this.active.get(identity);
    if (prior && prior.expiresAt > now) throw new Error('a Codex device-auth task is already active for this principal');
    if (prior) await this.expireActive(identity, prior.taskId, prior.expiresAt);
    const taskId = randomUUID();
    const expiresAt = now + this.leaseMs;
    const authPath = this.input.authPathFor(key, taskId);
    await this.input.repository.beginCodexLoginTask({ key, taskId, leaseExpiresAt: new Date(expiresAt) });
    const active: ActiveCodexLoginTask = { taskId, expiresAt, key };
    this.active.set(identity, active);
    this.scheduleExpiry(identity, active);
    try {
      const challenge = await this.input.runner.startDeviceAuth({ authPath, timeoutMs: this.leaseMs });
      const stillActive = this.active.get(identity);
      if (!stillActive || stillActive.taskId !== taskId || stillActive.expiresAt <= this.now()) {
        throw new Error('Codex device-auth task expired');
      }
      await this.input.repository.updateCodexLoginTask(taskId, {
        status: 'pending', verificationUri: challenge.verificationUri, userCode: challenge.userCode,
      });
      await this.input.notifyDeviceChallenge?.(key, challenge);
      const afterNotify = this.active.get(identity);
      if (!afterNotify || afterNotify.taskId !== taskId || afterNotify.expiresAt <= this.now()) {
        throw new Error('Codex device-auth task expired');
      }
      return { taskId, status: 'pending', verificationUri: challenge.verificationUri, userCode: challenge.userCode, expiresAt: new Date(expiresAt).toISOString() };
    } catch (error) {
      const current = this.active.get(identity);
      if (current?.taskId === taskId) {
        await this.input.repository.updateCodexLoginTask(taskId, { status: 'failed', errorCode: 'device_auth_start_failed' }).catch(() => undefined);
      }
      try { removeCodexAuthMaterial(authPath); } catch { /* best effort, never follow a symlink */ }
      // A stale begin() can finish after its lease was reaped and a new
      // generation has claimed the same principal. Never let the old
      // promise clear the newer active task.
      this.clearActiveExact(identity, taskId);
      throw new Error(redactCredentialText(error));
    }
  }

  async complete(keyInput: AgentPrincipalKey, taskId: string, expectedVersion?: number): Promise<AgentCredentialMetadata> {
    const key = safeKey(keyInput);
    await this.requireEnabled(key);
    const identity = this.identity(key);
    const active = this.active.get(identity);
    if (!active || active.taskId !== taskId) {
      throw new Error('Codex device-auth task is missing or expired');
    }
    if (active.expiresAt <= this.now()) {
      await this.expireActive(identity, active.taskId, active.expiresAt);
      throw new Error('Codex device-auth task is missing or expired');
    }
    const authPath = this.input.authPathFor(key, taskId);
    let retryableIncomplete = false;
    let terminalOutcome = false;
    try {
      const status = await this.input.runner.status({ authPath });
      const stillActive = this.active.get(identity);
      if (!stillActive || stillActive.taskId !== taskId || stillActive.expiresAt <= this.now()) {
        throw new Error('Codex device-auth task is missing or expired');
      }
      if (!status.loggedIn) {
        // The user may still be completing the browser challenge.  Keep the
        // task lease, child process and auth file so a later complete can
        // retry without forcing a new login.
        retryableIncomplete = true;
        throw new Error('Codex device-auth is not complete');
      }
      const authJson = readFileSync(safeAuthPath(authPath), 'utf8');
      const metadata = await this.input.repository.putCredential({
        key, credentialKind: 'codex_chatgpt', secret: authJson, expectedVersion,
      });
      await this.input.stopSessionsForPrincipal?.(key);
      await this.input.repository.updateCodexLoginTask(taskId, { status: 'ready' });
      terminalOutcome = true;
      return metadata;
    } catch (error) {
      if (retryableIncomplete) throw new Error(redactCredentialText(error));
      terminalOutcome = true;
      this.clearActive(identity);
      // Any persistence, parsing, or CAS failure terminates this task.  The
      // typed CAS error is preserved for the HTTP/command mapper, while the
      // task state and local material are cleaned up below.
      await this.input.repository.updateCodexLoginTask(taskId, {
        status: 'failed', errorCode: 'device_auth_complete_failed',
      }).catch(() => undefined);
      // Preserve the typed CAS signal for callers, but never let a CLI/HTTP
      // error echo credential-shaped text into a dashboard or bot response.
      if (error && typeof error === 'object'
        && (error as { name?: unknown }).name === 'CredentialVersionConflictError') throw error;
      throw new Error(redactCredentialText(error));
    } finally {
      if (terminalOutcome) {
        this.clearActive(identity);
        await disposeRunner(this.input.runner, authPath);
        try { removeCodexAuthMaterial(authPath); } catch { /* fail closed; never retain a usable task */ }
      }
    }
  }

  async status(keyInput: AgentPrincipalKey): Promise<CodexLoginTaskView | undefined> {
    const key = safeKey(keyInput);
    await this.requireEnabled(key);
    const task = await this.input.repository.getCodexLoginTask?.(key);
    if (task) {
      const now = this.now();
      if (await this.reapExpiredStoredTask(key, task, now)) {
        return { taskId: task.taskId, status: 'expired', expiresAt: task.leaseExpiresAt };
      }
      return {
        taskId: task.taskId,
        status: task.status,
        ...(task.verificationUri ? { verificationUri: task.verificationUri } : {}),
        ...(task.userCode ? { userCode: task.userCode } : {}),
        expiresAt: task.leaseExpiresAt,
      };
    }
    const active = this.active.get(this.identity(key));
    return active ? { taskId: active.taskId, status: 'pending', expiresAt: new Date(active.expiresAt).toISOString() } : undefined;
  }

  async logout(keyInput: AgentPrincipalKey, taskId?: string): Promise<void> {
    const key = safeKey(keyInput);
    await this.requireEnabled(key);
    const identity = this.identity(key);
    // Logout supersedes lease expiry. Pause this generation while the task
    // lookup runs; an invalid task id must restore the timer and leave the
    // active login untouched.
    const active = this.active.get(identity);
    if (active?.timer) {
      clearTimeout(active.timer);
      active.timer = undefined;
    }
    let stored: AgentCodexLoginTaskRecord | undefined;
    let failure: unknown;
    const recordFailure = (error: unknown): void => { if (failure === undefined) failure = error; };
    try {
      stored = await this.input.repository.getCodexLoginTask?.(key);
    } catch (error) {
      // Continue local revocation/fencing even when the task lookup is
      // unavailable; the canonical cache and live worker must not survive a
      // failed logout request.
      recordFailure(error);
    }
    const currentTaskId = active?.taskId
      ?? (stored?.status === 'pending' ? stored.taskId : undefined);
    if (taskId !== undefined && taskId !== currentTaskId) {
      if (active && this.active.get(identity) === active) this.scheduleExpiry(identity, active);
      throw new Error('Codex device-auth task does not belong to this principal');
    }
    // A later begin may install a newer generation while an asynchronous
    // lookup was in flight; remove only this exact one before revocation.
    if (active) this.clearActiveExact(identity, active.taskId);
    const effectiveTaskId = taskId ?? currentTaskId;
    const authPath = this.input.authPathFor(key, effectiveTaskId ?? randomUUID());
    try { await this.input.runner.logout({ authPath }); } catch (error) { recordFailure(error); }
    // The runner contract's logout normally disposes itself, but keep the
    // service-level fence explicit so a partial/mock runner cannot leave a
    // device-auth child alive after a failed DB operation.
    await disposeRunner(this.input.runner, authPath);
    try { await this.input.repository.deleteCredential(key, undefined, 'codex_chatgpt'); } catch (error) { recordFailure(error); }
    try { removeCodexAuthMaterial(authPath); } catch (error) { recordFailure(error); }
    if (this.input.canonicalAuthPathFor) {
      try { removeCodexAuthMaterial(this.input.canonicalAuthPathFor(key)); } catch (error) { recordFailure(error); }
    }
    if (effectiveTaskId) {
      try {
        await this.input.repository.updateCodexLoginTask(effectiveTaskId, { status: 'logged_out' });
      } catch (error) { recordFailure(error); }
    }
    // A missing DB row does not prove that live sessions have stopped: a
    // worker may still hold the previously materialized auth inode.  Logout
    // is therefore an unconditional exact-principal lifecycle fence.
    try { await this.input.stopSessionsForPrincipal?.(key); } catch (error) { recordFailure(error); }
    if (failure !== undefined) {
      // Repository errors are already sanitized domain errors in production;
      // generic runner/driver failures must not echo process/DSN/credential
      // text through the command or dashboard boundary.
      if (failure instanceof AgentPrincipalLookupError
        || (failure && typeof failure === 'object'
          && (failure as { name?: unknown }).name === 'CredentialVersionConflictError')) {
        throw failure;
      }
      throw new Error('Codex logout failed');
    }
  }
}

/** Watch only the current principal's materialized auth file. */
export class CodexAuthRefreshWatcher {
  private watcher: FSWatcher | undefined;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private lastBody?: string;
  private credentialVersion: number;
  private failed = false;

  constructor(private readonly input: {
    readonly authPath: string;
    readonly key: AgentPrincipalKey;
    readonly repository: Pick<AgentPrincipalRepository, 'putCredential'> & {
      /** Read the current row after a CAS loss to converge same-body refreshes. */
      readonly readSecret?: AgentPrincipalRepository['readSecret'];
    };
    readonly credentialVersion: number;
    readonly onVersionConflict?: () => Promise<void> | void;
    /** Any watcher/read/refresh failure invalidates this sandbox instance. */
    readonly onRefreshFailure?: (error: unknown) => Promise<void> | void;
  }) {
    this.credentialVersion = input.credentialVersion;
  }

  start(): void {
    if (this.watcher) return;
    // `watch()` follows the parent directory. safeAuthPath rejects symlinked
    // components and also makes initialization fail closed when the mount is
    // missing or has been replaced by a non-directory.
    try {
      safeAuthPath(this.input.authPath);
      const watcher = watch(dirname(this.input.authPath), (_event, name) => {
        if (!name || name.toString() !== 'auth.json') return;
        if (this.timer) clearTimeout(this.timer);
        this.timer = setTimeout(() => { void this.flush(); }, 100);
        this.timer.unref?.();
      });
      // fs.watch reports a removed/replaced auth directory asynchronously.
      // Treat that exactly like a refresh failure: close the watcher and let
      // the worker lifecycle stop the sandbox instead of silently continuing
      // with a credential file that is no longer under the trusted root.
      watcher.on('error', error => { void this.failClosed(error); });
      this.watcher = watcher;
    } catch (error) {
      void this.failClosed(error);
      throw error;
    }
  }

  async flush(): Promise<void> {
    if (this.failed) return;
    this.timer = undefined;
    let stat;
    try { stat = lstatSync(this.input.authPath); } catch (error) { await this.failClosed(error); return; }
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 2 * 1024 * 1024) {
      await this.failClosed(new Error('Codex auth refresh material is not a regular bounded file'));
      return;
    }
    let body: string;
    try {
      body = readFileSync(this.input.authPath, 'utf8');
      JSON.parse(body);
      if (!authJsonIsLoggedIn(this.input.authPath)) throw new Error('Codex auth refresh material has no usable token');
    }
    catch (error) { await this.failClosed(error); return; }
    if (body === this.lastBody) return;
    try {
      const metadata = await this.input.repository.putCredential({
        key: this.input.key, credentialKind: 'codex_chatgpt', secret: body, expectedVersion: this.credentialVersion,
      });
      this.credentialVersion = metadata.credentialVersion;
      this.lastBody = body;
    } catch (error) {
    if (error instanceof Error && (error.message === 'credential_version_conflict'
      || error.name === 'CredentialVersionConflictError')) {
        // Multiple topics for one principal share the canonical auth file. A
        // simultaneous refresh can therefore race on the same body: if the
        // winner stored exactly this material, adopt its version and keep the
        // session alive. A different body still means another actor rotated
        // the credential and this frozen session must fail closed.
        if (this.input.repository.readSecret) {
          try {
            const current = await this.input.repository.readSecret(this.input.key);
            if (current.metadata.credentialKind === 'codex_chatgpt'
              && current.metadata.credentialVersion > this.credentialVersion
              && current.secret === body) {
              this.credentialVersion = current.metadata.credentialVersion;
              this.lastBody = body;
              return;
            }
          } catch {
            // A failed/disabled read is not evidence that this body won. Fail
            // closed below without copying any database or credential text.
          }
        }
        // A CAS loss with a different body means this worker no longer owns
        // the credential lease. Notify the lifecycle owner, then fail closed
        // even if that callback is absent or cannot stop the host process.
        try { await this.input.onVersionConflict?.(); } catch { /* fail closed below */ }
        await this.failClosed(error);
      } else {
        await this.failClosed(error);
      }
    }
  }

  private async failClosed(error: unknown): Promise<void> {
    if (this.failed) return;
    this.failed = true;
    this.stop();
    try { await this.input.onRefreshFailure?.(error); } catch { /* never reopen a failed watcher */ }
  }

  stop(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    this.watcher?.close();
    this.watcher = undefined;
  }
}
