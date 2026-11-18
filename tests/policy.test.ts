import { describe, expect, it } from 'vitest';
import {
  ActionRegistry,
  AgentsError,
  assertActionName,
  assertActorId,
  assertPrincipal,
  digestOf,
  normaliseScopes,
  streamOf,
} from '../src/index.js';

const codeOf = (error: unknown): string => (error as AgentsError).code;

describe('action names', () => {
  it('accepts lowercase dotted names and trims outer whitespace', () => {
    expect(assertActionName(' notes.create ')).toBe('notes.create');
    expect(assertActionName('vault.read')).toBe('vault.read');
    expect(assertActionName('a:b-c_d')).toBe('a:b-c_d');
  });

  it('rejects anything that would be ambiguous in a receipt', () => {
    for (const bad of [
      '',
      ' ',
      'Notes.Create',
      '1notes',
      'notes create',
      'notes\ncreate',
      42,
      null,
    ]) {
      expect(() => assertActionName(bad)).toThrow(AgentsError);
      try {
        assertActionName(bad);
      } catch (error) {
        expect(codeOf(error)).toBe('invalid-action');
      }
    }
  });

  it('rejects names over the length bound', () => {
    expect(() => assertActionName('a'.repeat(129))).toThrow(AgentsError);
  });
});

describe('principals', () => {
  it('normalises a valid principal and dedupes scopes', () => {
    expect(
      assertPrincipal({
        id: ' agent:planner ',
        scopes: ['notes:write', 'notes:write', 'vault.read'],
      })
    ).toEqual({ id: 'agent:planner', scopes: ['notes:write', 'vault.read'] });
    expect(assertPrincipal({ id: 'agent:reader' })).toEqual({ id: 'agent:reader', scopes: [] });
  });

  it('rejects non-objects, empty ids and control characters', () => {
    for (const bad of [null, undefined, 'agent', 42, [], {}, { id: '   ' }, { id: 'a\u0000b' }]) {
      expect(() => assertPrincipal(bad)).toThrow(AgentsError);
    }
    try {
      assertPrincipal({ id: 'a\nb' });
    } catch (error) {
      expect(codeOf(error)).toBe('invalid-principal');
    }
  });

  it('rejects ids over 200 characters', () => {
    expect(() => assertActorId('a'.repeat(201))).toThrow(AgentsError);
  });

  it('rejects malformed scopes', () => {
    expect(() => assertPrincipal({ id: 'a', scopes: 'notes:write' })).toThrow(AgentsError);
    expect(() => assertPrincipal({ id: 'a', scopes: [42] })).toThrow(AgentsError);
    expect(() => assertPrincipal({ id: 'a', scopes: ['Notes Write'] })).toThrow(AgentsError);
    expect(() =>
      assertPrincipal({ id: 'a', scopes: Array.from({ length: 33 }, (_, i) => `scope:${i}`) })
    ).toThrow(AgentsError);
  });

  it('normaliseScopes defaults to none and trims entries', () => {
    expect(normaliseScopes(undefined, 'invalid-action', 'scopes')).toEqual([]);
    expect(normaliseScopes([' notes:read '], 'invalid-action', 'scopes')).toEqual(['notes:read']);
  });
});

describe('digests', () => {
  it('is independent of object key order', () => {
    expect(digestOf({ a: 1, b: [2, 3] })).toBe(digestOf({ b: [2, 3], a: 1 }));
  });

  it('changes when the request changes', () => {
    expect(digestOf({ amount: 10 })).not.toBe(digestOf({ amount: 11 }));
    expect(digestOf(undefined)).toBe(digestOf(null));
  });

  it('has a stable stream per actor and a different stream across actors', () => {
    expect(streamOf('agent:a')).toBe(streamOf('agent:a'));
    expect(streamOf('agent:a')).not.toBe(streamOf('agent:b'));
    expect(streamOf('agent:a')).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('ActionRegistry', () => {
  it('registers with defaults and reports a sorted allow-list', () => {
    const registry = new ActionRegistry();
    registry.define('notes.delete', () => null);
    registry.define('notes.create', () => null);
    expect(registry.names()).toEqual(['notes.create', 'notes.delete']);
    expect(registry.get('notes.create')?.policy).toEqual({ scopes: [] });
    expect(registry.get('missing')).toBeUndefined();
  });

  it('refuses to overwrite a registered action', () => {
    const registry = new ActionRegistry();
    registry.define('notes.create', () => null);
    expect(() => registry.define('notes.create', () => null)).toThrow(AgentsError);
    try {
      registry.define('notes.create', () => null);
    } catch (error) {
      expect(codeOf(error)).toBe('duplicate-action');
    }
  });

  it('validates handler and policy', () => {
    const registry = new ActionRegistry();
    expect(() => registry.define('notes.create', 'not-a-function')).toThrow(AgentsError);
    expect(() => registry.define('notes.create', () => null, null as never)).toThrow(AgentsError);
    expect(() => registry.define('notes.create', () => null, [] as never)).toThrow(AgentsError);
    expect(() => registry.define('notes.create', () => null, { mutating: 'yes' } as never)).toThrow(
      AgentsError
    );
    expect(() => registry.define('notes.create', () => null, { description: '  ' })).toThrow(
      AgentsError
    );
    expect(() => registry.define('notes.create', () => null, { scopes: ['Bad Scope'] })).toThrow(
      AgentsError
    );
  });

  it('keeps only the documented policy fields', () => {
    const registry = new ActionRegistry();
    const registered = registry.define('notes.create', () => null, {
      scopes: ['notes:write'],
      mutating: true,
      description: ' Create a note ',
      // Extra keys are not copied into the receipt-facing policy.
      ...({ injected: 'x' } as object),
    });
    expect(registered.policy).toEqual({
      scopes: ['notes:write'],
      mutating: true,
      description: 'Create a note',
    });
  });
});
