import { describe, expect, it } from 'vitest';
import { buildPrincipalSeedRows } from '../src/services/agent-principal-seed.js';

const owners = new Map([
  ['app_a', 'ou_ownerA'],
  ['app_b', 'ou_ownerB'],
]);

describe('T8 principal seed identity mappings', () => {
  it('lets an exact app/raw mapping override a syntactically valid copied open_id', () => {
    const rows = buildPrincipalSeedRows({
      bots: [
        { larkAppId: 'app_a', allowedUsers: ['ou_copiedB', 'ou_shared'] },
        { larkAppId: 'app_b', allowedUsers: ['ou_copiedB', 'ou_shared'] },
      ],
      ownerOpenIds: owners,
      userOpenIdMappings: new Map([
        ['app_a\0ou_copiedB', 'ou_appACorrect'],
      ]),
    });

    expect(rows.map(row => [row.key.larkAppId, row.key.openId])).toEqual([
      ['app_a', 'ou_appACorrect'],
      ['app_a', 'ou_shared'],
      ['app_a', 'ou_ownerA'],
      ['app_b', 'ou_copiedB'],
      ['app_b', 'ou_shared'],
      ['app_b', 'ou_ownerB'],
    ]);
    expect(rows.find(row => row.key.larkAppId === 'app_a' && row.key.openId === 'ou_copiedB')).toBeUndefined();
  });

  it('deduplicates several raw entries that map to one principal within an app', () => {
    const rows = buildPrincipalSeedRows({
      bots: [{ larkAppId: 'app_a', allowedUsers: ['ou_legacy', 'ou_legacy', 'alice@example.com'] }],
      ownerOpenIds: new Map([['app_a', 'ou_ownerA']]),
      userOpenIdMappings: new Map([
        ['app_a\0ou_legacy', 'ou_canonical'],
        ['app_a\0alice@example.com', 'ou_canonical'],
      ]),
    });

    expect(rows).toEqual([
      { key: { larkAppId: 'app_a', openId: 'ou_canonical' }, canOpenMemory: false, reason: 'allowed_user' },
      { key: { larkAppId: 'app_a', openId: 'ou_ownerA' }, canOpenMemory: true, reason: 'explicit_owner' },
    ]);
  });

  it('fails closed for malformed, unknown-app, conflicting, and unconsumed mappings', () => {
    const input = {
      bots: [{ larkAppId: 'app_a', allowedUsers: ['alice@example.com'] }],
      ownerOpenIds: new Map([['app_a', 'ou_ownerA']]),
    };
    expect(() => buildPrincipalSeedRows({
      ...input,
      userOpenIdMappings: new Map([['app_missing\0alice@example.com', 'ou_target']]),
    })).toThrow(/absent from bots config/);
    expect(() => buildPrincipalSeedRows({
      ...input,
      userOpenIdMappings: new Map([['app_a\0', 'ou_target']]),
    })).toThrow(/non-empty raw-config-value/);
    expect(() => buildPrincipalSeedRows({
      ...input,
      userOpenIdMappings: new Map([['app_a\0alice@example.com', 'not-an-open-id']]),
    })).toThrow(/target must be an app-scoped open_id/);
    expect(() => buildPrincipalSeedRows({
      bots: [{ larkAppId: 'app_a', allowedUsers: ['ou_ownerA'] }],
      ownerOpenIds: input.ownerOpenIds,
      userOpenIdMappings: new Map([['app_a\0not-in-allowed-users', 'ou_target']]),
    })).toThrow(/unused --map mapping/);

    const conflictingEntries = {
      *[Symbol.iterator](): IterableIterator<[string, string]> {
        yield ['app_a\0alice@example.com', 'ou_first'];
        yield ['app_a\0alice@example.com', 'ou_second'];
      },
    };
    expect(() => buildPrincipalSeedRows({
      ...input,
      userOpenIdMappings: conflictingEntries as unknown as ReadonlyMap<string, string>,
    })).toThrow(/conflicting values/);
  });

  it('marks only the exact owner principal as MemoryGate-capable and returns the final rows', () => {
    const rows = buildPrincipalSeedRows({
      bots: [{ larkAppId: 'app_a', allowedUsers: ['ou_ownerA', 'ou_other'] }],
      ownerOpenIds: new Map([['app_a', 'ou_ownerA']]),
      explicitOpenIds: [{ larkAppId: 'app_a', openId: 'ou_other' }],
    });

    expect(rows).toEqual([
      { key: { larkAppId: 'app_a', openId: 'ou_ownerA' }, canOpenMemory: true, reason: 'explicit_owner' },
      { key: { larkAppId: 'app_a', openId: 'ou_other' }, canOpenMemory: false, reason: 'allowed_user' },
    ]);
    expect(rows.filter(row => row.canOpenMemory).map(row => row.key)).toEqual([{ larkAppId: 'app_a', openId: 'ou_ownerA' }]);
  });
});
