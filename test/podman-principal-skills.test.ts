import { describe, expect, it } from 'vitest';
import {
  buildCredentialInjectionPlan,
  buildPodmanMountPlan,
  buildSessionRuntimePaths,
  normalizePrincipalSkillBindings,
  parsePodmanExecutionConfig,
} from '../src/execution/podman-execution.js';

const config = parsePodmanExecutionConfig({
  type: 'podman',
  image: 'localhost/botmux-quant-dev@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  sourceRepo: '/srv/analyze', sourceBranch: 'main',
  runtimeRoot: '/srv/.botmux/runtime', credentialCacheRoot: '/srv/.botmux/credential-cache',
  dataRoot: '/srv/analyze/apps/quant-qlib/data',
  knowledgeRoot: '/srv/analyze/apps/quant-qlib/knowledge/investment-books',
  ownerMemoryGate: '127.0.0.1:18181', idleTimeoutMinutes: 60, memory: '1g', cpus: 1,
});
describe('Podman principal skill mounts', () => {
  it('mounts only named skill leaves read-only into the selected harness root', () => {
    const principal = { larkAppId: 'cli_a', openId: 'ou_guest' } as const;
    const runtime = buildSessionRuntimePaths(config, principal, 'session');
    const credential = buildCredentialInjectionPlan({
      cliId: 'claude-code', credentialKind: 'api', credentialVersion: 1,
      sessionHome: runtime.homeRoot, baseUrl: 'https://api.example.com/v1', model: 'claude',
    });
    const skills = [{ name: 'sanity', rootDir: '/mnt/c/Users/admin/.codex/skills/sanity', entrypoint: 'SKILL.md' }] as const;
    const mounts = buildPodmanMountPlan(config, runtime, credential, skills);
    expect(mounts.at(-1)).toEqual({
      source: skills[0].rootDir,
      target: '/home/dev/.claude/skills/sanity',
      mode: 'ro',
      kind: 'principal-skill',
    });
    expect(mounts.filter(mount => mount.kind === 'principal-skill')).toHaveLength(1);
  });

  it('rejects an entire skills root, traversal, and duplicate names', () => {
    expect(() => normalizePrincipalSkillBindings('codex', [{ name: 'sanity', rootDir: '/mnt/c/Users/admin/.codex/skills', entrypoint: 'SKILL.md' }]))
      .toThrow(/leaf directory/);
    expect(() => normalizePrincipalSkillBindings('codex', [{ name: 'sanity', rootDir: '/mnt/c/Users/admin/.codex/skills/../sanity', entrypoint: 'SKILL.md' }]))
      .toThrow(/traversal/);
    expect(() => normalizePrincipalSkillBindings('codex', [
      { name: 'sanity', rootDir: '/mnt/c/Users/admin/.codex/skills/sanity', entrypoint: 'SKILL.md' },
      { name: 'sanity', rootDir: '/mnt/c/Users/admin/.codex/skills/sanity', entrypoint: 'SKILL.md' },
    ])).toThrow(/duplicate/);
  });
});
