import { afterEach, describe, expect, it } from 'vitest';
import { chmodSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  AGENT_PRINCIPAL_SKILLS_UP_SQL,
  DEFAULT_PRINCIPAL_SKILL_NAMES,
  discoverDefaultPrincipalSkills,
  freezePrincipalSkillRows,
  readPrincipalSkillRows,
  replacePrincipalSkillRows,
  validatePrincipalSkillRoot,
  type AgentPrincipalSkillRow,
} from '../src/services/agent-principal-skills.js';

const cleanup: string[] = [];
afterEach(() => { for (const path of cleanup.splice(0)) rmSync(path, { recursive: true, force: true }); });

function tempRoot(): string {
  const path = join(tmpdir(), `botmux-principal-skills-${Date.now()}-${Math.random().toString(16).slice(2)}`);
  mkdirSync(path, { recursive: true, mode: 0o700 });
  cleanup.push(path);
  return path;
}

describe('principal skill policy', () => {
  it('keeps the independent table migration app-scoped and read-only compatible', () => {
    expect(AGENT_PRINCIPAL_SKILLS_UP_SQL).toContain('agent_principal_skills');
    expect(AGENT_PRINCIPAL_SKILLS_UP_SQL).toContain('PRIMARY KEY (lark_app_id, open_id, skill_name)');
    expect(AGENT_PRINCIPAL_SKILLS_UP_SQL).toContain('FOREIGN KEY (lark_app_id, open_id)');
    expect(AGENT_PRINCIPAL_SKILLS_UP_SQL).toContain('skill_root LIKE \'/%\'');
  });

  it('discovers only the three approved leaves, never the whole skills root', () => {
    const root = tempRoot();
    for (const name of DEFAULT_PRINCIPAL_SKILL_NAMES) {
      mkdirSync(join(root, name), { recursive: true, mode: 0o700 });
      writeFileSync(join(root, name, 'SKILL.md'), `# ${name}\n`, { mode: 0o600 });
    }
    mkdirSync(join(root, 'not-approved'), { mode: 0o700 });
    const found = discoverDefaultPrincipalSkills({ roots: [root] });
    expect(found.map(skill => skill.name)).toEqual([...DEFAULT_PRINCIPAL_SKILL_NAMES]);
    expect(found.every(skill => skill.rootDir !== root)).toBe(true);
    expect(found.every(skill => skill.entrypoint === 'SKILL.md')).toBe(true);
  });

  it('rejects traversal and freezes only an approved skills leaf', () => {
    expect(() => validatePrincipalSkillRoot('/tmp/skills/../secrets')).toThrow();
    const root = tempRoot();
    const skillsRoot = join(root, 'skills');
    const skillRoot = join(skillsRoot, 'sanity');
    mkdirSync(skillRoot, { recursive: true, mode: 0o700 });
    writeFileSync(join(skillRoot, 'SKILL.md'), '# sanity\n', { mode: 0o600 });
    const row: AgentPrincipalSkillRow = {
      larkAppId: 'cli_a', openId: 'ou_guest', name: 'sanity', rootDir: skillRoot,
      enabled: true, priority: 0, createdAt: '', updatedAt: '',
    };
    expect(freezePrincipalSkillRows([row])).toEqual([expect.objectContaining({ name: 'sanity', rootDir: skillRoot })]);
    chmodSync(join(skillRoot, 'SKILL.md'), 0o000);
  });

  it('reads rows in DB priority order and replaces them atomically', async () => {
    const calls: Array<{ text: string; values?: readonly unknown[] }> = [];
    const db = {
      query: async <Row extends Record<string, unknown>>(text: string, values?: readonly unknown[]) => {
        calls.push({ text, values });
        if (text.startsWith('SELECT')) {
          return { rows: [{
            lark_app_id: 'cli_a', open_id: 'ou_guest', skill_name: 'sanity', skill_root: '/tmp/skills/sanity',
            enabled: true, priority: 0, created_at: new Date(0), updated_at: new Date(0),
          }] as Row[] };
        }
        return { rows: [] as Row[] };
      },
      connect: async () => { throw new Error('pool transaction not used in read'); },
    };
    const rows = await readPrincipalSkillRows(db, { larkAppId: 'cli_a', openId: 'ou_guest' });
    expect(rows[0]?.name).toBe('sanity');
    expect(calls[0]?.values).toEqual(['cli_a', 'ou_guest']);

    const txCalls: string[] = [];
    const tx = {
      query: async <Row extends Record<string, unknown>>(text: string) => {
        txCalls.push(text);
        return { rows: text.startsWith('INSERT') ? [{
          lark_app_id: 'cli_a', open_id: 'ou_guest', skill_name: 'sanity', skill_root: '/tmp/skills/sanity',
          enabled: true, priority: 1, created_at: new Date(0), updated_at: new Date(0),
        }] as Row[] : [] as Row[] };
      },
      release: () => undefined,
    };
    await replacePrincipalSkillRows({ query: tx.query, connect: async () => tx }, { larkAppId: 'cli_a', openId: 'ou_guest' }, [
      { name: 'sanity', rootDir: '/tmp/skills/sanity', enabled: true, priority: 1 },
    ]);
    expect(txCalls[0]).toBe('BEGIN');
    expect(txCalls.some(text => text.includes('DELETE FROM agent_principal_skills'))).toBe(true);
    expect(txCalls.at(-1)).toBe('COMMIT');
  });
});
