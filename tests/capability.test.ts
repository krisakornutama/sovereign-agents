import { describe, expect, it } from 'vitest';
import { Attest } from 'sovereign-attest';
import {
  CAPABILITY_ISSUED,
  AgentsError,
  capabilityStream,
  grantMeta,
  missingScopes,
  normaliseGrant,
  openCapability,
} from '../src/index.js';
import { makeGate } from './helpers.js';

const codeOf = (error: unknown): string => (error as AgentsError).code;

// 64 hex: a receipt id / artifact digest, not the 32-hex key fingerprint.
const FP = 'a1'.repeat(32);

function manualClock(start = 1_700_000_000_000): {
  now: () => number;
  advance: (ms: number) => void;
} {
  let value = start;
  return {
    now: () => value,
    advance: (ms) => {
      value += ms;
    },
  };
}

async function notesGate(settings: Parameters<typeof makeGate>[0] = {}) {
  const fixture = await makeGate(settings);
  const calls: string[] = [];
  fixture.gate.register<{ text: string }>(
    'notes.create',
    (args) => {
      calls.push(`create:${args.text}`);
      return { id: 'note-1' };
    },
    { scopes: ['notes:write'], mutating: true }
  );
  fixture.gate.register(
    'notes.read',
    () => {
      calls.push('read');
      return [];
    },
    { scopes: ['notes:read'] }
  );
  fixture.gate.register(
    'notes.delete',
    () => {
      calls.push('delete');
      return null;
    },
    { scopes: ['notes:write'] }
  );
  return { ...fixture, calls };
}

describe('capability grants', () => {
  it('normalises a grant and keeps only what it grants', () => {
    expect(
      normaliseGrant({
        subject: ' agent:planner ',
        scopes: ['notes:write', 'notes:write'],
        actions: ['notes.create', 'notes.create'],
        expiresAt: 1_700_000_060_000,
      })
    ).toEqual({
      subject: 'agent:planner',
      scopes: ['notes:write'],
      actions: ['notes.create'],
      expiresAt: 1_700_000_060_000,
    });
    expect(normaliseGrant({ subject: 'a', scopes: [], expiresAt: 5 })).toEqual({
      subject: 'a',
      scopes: [],
      expiresAt: 5,
    });
  });

  it('refuses grants that would be a password: no expiry, no subject, bad window', () => {
    for (const bad of [
      null,
      'agent:planner',
      {},
      { subject: '', expiresAt: 10 },
      { subject: 'a' },
      { subject: 'a', expiresAt: -1 },
      { subject: 'a', expiresAt: 10, notBefore: 10 },
      { subject: 'a', expiresAt: 10, notBefore: 20 },
      { subject: 'a', expiresAt: 10, scopes: 'notes:write' },
      { subject: 'a', expiresAt: 10, scopes: ['Notes Write'] },
      { subject: 'a', expiresAt: 10, actions: 'notes.create' },
      { subject: 'a', expiresAt: 10, actions: ['Notes.Create'] },
      {
        subject: 'a',
        expiresAt: 10,
        actions: Array.from({ length: 65 }, (_, i) => `action:${i}`),
      },
    ]) {
      expect(() => normaliseGrant(bad)).toThrow(AgentsError);
      try {
        normaliseGrant(bad);
      } catch (error) {
        expect(codeOf(error)).toBe('invalid-capability');
      }
    }
  });

  it('derives the revocation stream from the token id only', () => {
    expect(capabilityStream(FP)).toBe(capabilityStream(FP));
    expect(capabilityStream(FP)).not.toBe(capabilityStream('0'.repeat(64)));
    expect(() => capabilityStream('not-a-digest')).toThrow(AgentsError);
  });

  it('reports the scopes a token does not hold', () => {
    const capability = {
      id: FP,
      issuer: 'agent:issuer',
      subject: 'agent:planner',
      scopes: ['notes:read'],
      actions: null,
      notBefore: 0,
      expiresAt: 10,
      issuedAt: 0,
      receipt: {} as never,
    };
    expect(missingScopes(capability, ['notes:write', 'notes:read'])).toEqual(['notes:write']);
    expect(missingScopes(capability, [])).toEqual([]);
  });
});

describe('issuing tokens', () => {
  it('seals a verifiable token that carries its own grant', async () => {
    const { gate } = await notesGate();
    const token = await gate.issueCapability({
      subject: 'agent:planner',
      scopes: ['notes:read', 'notes:write'],
      expiresAt: 1_700_000_060_000,
    });

    expect(token.subject).toBe('agent:planner');
    expect(token.scopes).toEqual(['notes:read', 'notes:write']);
    expect(token.actions).toBeNull();
    expect(token.receipt.body.action).toBe(CAPABILITY_ISSUED);
    expect(token.receipt.body.meta?.grant).toBe(
      grantMeta(
        normaliseGrant({
          subject: 'agent:planner',
          scopes: ['notes:read', 'notes:write'],
          expiresAt: 1_700_000_060_000,
        })
      ).grant
    );

    // The token is a normal receipt: any verifier that pins the key can read it.
    expect(gate.verify(token.receipt).meta?.subject).toBe('agent:planner');
    expect(await gate.capabilityState(token.receipt)).toEqual({
      revoked: false,
      at: null,
      receipt: null,
    });

    // It also verifies without a gate, from the receipt alone.
    expect(openCapability(token.receipt, { publicKey: gate.publicKey }).subject).toBe(
      'agent:planner'
    );
  });

  it('rejects a genuine receipt that is not a capability', async () => {
    const { gate } = await notesGate();
    const ordinary = await gate
      .run({ id: 'agent:planner', scopes: ['notes:read'] }, 'notes.read')
      .then((run) => run.receipts.requested)
      .catch(() => null);
    expect(ordinary).not.toBeNull();
    expect(() => openCapability(ordinary, { publicKey: gate.publicKey })).toThrow(AgentsError);
    try {
      openCapability(ordinary, { publicKey: gate.publicKey });
    } catch (error) {
      expect(codeOf(error)).toBe('invalid-capability');
    }
  });

  it('rejects a signed capability whose meta does not hash its grant', async () => {
    const { vault, clock } = await notesGate();
    const attest = await Attest.open({ vault, keyId: 'agent-gate', now: clock });
    const receipt = await attest.record({
      action: CAPABILITY_ISSUED,
      actor: 'agent:issuer',
      artifact: { name: 'agent-capability:agent:planner', sha256: FP },
      meta: {
        subject: 'agent:planner',
        scopes: 'notes:write',
        expiresAt: 1_700_000_060_000,
        grant: 'deadbeef',
      },
    });
    expect(() =>
      openCapability(receipt, { trustedKeys: { 'agent-gate': attest.publicKey } })
    ).toThrow(AgentsError);
  });
});

describe('running with a capability', () => {
  it('runs an action the token covers and records the token id on the request', async () => {
    const { gate, calls } = await notesGate();
    const token = await gate.issueCapability({
      subject: 'agent:planner',
      scopes: ['notes:write'],
      expiresAt: 1_700_000_060_000,
    });

    const run = await gate.runWithCapability<{ id: string }>(token.receipt, 'notes.create', {
      text: 'self-hosted',
    });
    expect(run.value).toEqual({ id: 'note-1' });
    expect(calls).toEqual(['create:self-hosted']);
    expect(run.receipts.requested.body.actor).toBe('agent:planner');
    expect(run.receipts.requested.body.meta?.capability).toBe(token.id);

    const history = await gate.verifyHistory('agent:planner');
    expect(history.count).toBe(2);
  });

  it('refuses an action outside the token scopes, receipts the refusal, and runs nothing', async () => {
    const denials: string[] = [];
    const { gate, calls } = await notesGate({
      onDenied: (record) => denials.push(`${record.reason}:${record.actor}:${record.action}`),
    });
    const token = await gate.issueCapability({
      subject: 'agent:planner',
      scopes: ['notes:read'],
      expiresAt: 1_700_000_060_000,
    });

    await expect(
      gate.runWithCapability(token.receipt, 'notes.create', { text: 'nope' })
    ).rejects.toMatchObject({ code: 'missing-scope' });
    expect(calls).toEqual([]);
    expect(denials).toEqual(['missing-scope:agent:planner:notes.create']);

    const denial = (await gate.history('agent:planner')).at(-1);
    expect(denial?.body.action).toBe('agent.action.denied');
    expect(denial?.body.meta?.missingScopes).toBe('notes:write');
    expect(denial?.body.meta?.capability).toBe(token.id);

    // Reading is inside the token, so this one still works.
    await expect(gate.runWithCapability(token.receipt, 'notes.read')).resolves.toMatchObject({
      ok: true,
    });
    expect(calls).toEqual(['read']);
  });

  it('a token narrowed to named actions cannot be spent on a sibling action', async () => {
    const { gate, calls } = await notesGate();
    const token = await gate.issueCapability({
      subject: 'agent:planner',
      scopes: ['notes:read', 'notes:write'],
      actions: ['notes.create'],
      expiresAt: 1_700_000_060_000,
    });

    await expect(gate.runWithCapability(token.receipt, 'notes.delete')).rejects.toMatchObject({
      code: 'missing-scope',
    });
    expect(calls).toEqual([]);
    const denial = (await gate.history('agent:planner')).at(-1);
    expect(denial?.body.meta?.reason).toBe('out-of-scope-action');
    expect(denial?.body.meta?.grantedActions).toBe('notes.create');

    await expect(
      gate.runWithCapability(token.receipt, 'notes.create', { text: 'ok' })
    ).resolves.toMatchObject({ ok: true });
  });

  it('refuses an unregistered action and receipts it', async () => {
    const { gate } = await notesGate();
    const token = await gate.issueCapability({
      subject: 'agent:planner',
      scopes: ['notes:write'],
      expiresAt: 1_700_000_060_000,
    });
    await expect(gate.runWithCapability(token.receipt, 'notes.archive')).rejects.toMatchObject({
      code: 'unknown-action',
    });
    expect((await gate.history('agent:planner')).at(-1)?.body.meta?.reason).toBe('unknown-action');
  });

  it('refuses arguments that cannot be receipted', async () => {
    const { gate } = await notesGate();
    const token = await gate.issueCapability({
      subject: 'agent:planner',
      scopes: ['notes:write'],
      expiresAt: 1_700_000_060_000,
    });
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    await expect(
      gate.runWithCapability(token.receipt, 'notes.create', circular)
    ).rejects.toMatchObject({ code: 'invalid-args' });
  });

  it('reports a handler that throws, with a failed receipt already written', async () => {
    const { gate, clock } = await notesGate();
    gate.register('notes.explode', () => {
      throw new Error('boom');
    });
    const token = await gate.issueCapability({
      subject: 'agent:planner',
      scopes: [],
      expiresAt: 1_700_000_060_000,
    });
    const error = await gate
      .runWithCapability(token.receipt, 'notes.explode')
      .catch((thrown: AgentsError) => thrown);
    expect(error).toMatchObject({ code: 'handler-failed' });
    expect((error as AgentsError).receiptId).toBeDefined();
    expect(clock()).toBeGreaterThan(0);
  });
});

describe('refusing tokens that should never grant anything', () => {
  it('refuses an expired token', async () => {
    const clock = manualClock();
    const { gate, calls } = await notesGate({ clock: clock.now });
    const token = await gate.issueCapability({
      subject: 'agent:planner',
      scopes: ['notes:read'],
      expiresAt: clock.now() + 1_000,
    });
    clock.advance(5_000);

    await expect(gate.runWithCapability(token.receipt, 'notes.read')).rejects.toMatchObject({
      code: 'expired-capability',
    });
    expect(calls).toEqual([]);
    expect((await gate.history('agent:planner')).at(-1)?.body.meta?.reason).toBe(
      'expired-capability'
    );
  });

  it('refuses a token that is not valid yet', async () => {
    const clock = manualClock();
    const { gate } = await notesGate({ clock: clock.now });
    const token = await gate.issueCapability({
      subject: 'agent:planner',
      scopes: ['notes:read'],
      notBefore: clock.now() + 10_000,
      expiresAt: clock.now() + 20_000,
    });
    await expect(gate.runWithCapability(token.receipt, 'notes.read')).rejects.toMatchObject({
      code: 'capability-not-yet-valid',
    });
  });

  it('refuses a token whose scopes were edited after signing', async () => {
    const { gate, calls } = await notesGate();
    const token = await gate.issueCapability({
      subject: 'agent:planner',
      scopes: ['notes:read'],
      expiresAt: 1_700_000_060_000,
    });
    const forged = structuredClone(token.receipt) as typeof token.receipt & {
      body: { meta: Record<string, string | number> };
    };
    forged.body.meta.scopes = 'notes:read,notes:write';

    await expect(
      gate.runWithCapability(forged, 'notes.create', { text: 'x' })
    ).rejects.toMatchObject({ code: 'invalid-capability' });
    expect(calls).toEqual([]);
    expect((await gate.history('agent:planner')).at(-1)?.body.meta?.reason).toBe(
      'invalid-capability'
    );
  });

  it('refuses a token signed by an issuer the gate has not pinned', async () => {
    const other = await notesGate({ keyId: 'issuer-b', issuer: 'agent:issuer-b' });
    const token = await other.gate.issueCapability({
      subject: 'agent:planner',
      scopes: ['notes:write'],
      expiresAt: 1_700_000_060_000,
    });

    const local = await notesGate();
    await expect(
      local.gate.runWithCapability(token.receipt, 'notes.create', { text: 'x' })
    ).rejects.toMatchObject({ code: 'foreign-issuer' });
    expect(local.calls).toEqual([]);
    expect((await local.gate.history('agent:planner')).at(-1)?.body.meta?.reason).toBe(
      'foreign-issuer'
    );

    // Pinning that key is what makes the same token usable, not the token's own claim.
    const trusting = await notesGate({ capabilityIssuers: { 'issuer-b': other.gate.publicKey } });
    await expect(
      trusting.gate.runWithCapability(token.receipt, 'notes.create', { text: 'x' })
    ).resolves.toMatchObject({ ok: true });
    expect(trusting.calls).toEqual(['create:x']);
  });

  it('refuses a revoked token, and revocation itself is a receipt', async () => {
    const { gate, calls } = await notesGate();
    const token = await gate.issueCapability({
      subject: 'agent:planner',
      scopes: ['notes:write'],
      expiresAt: 1_700_000_060_000,
    });
    const revocation = await gate.revokeCapability(token.receipt, 'role changed');
    expect(revocation.body.action).toBe('agent.capability.revoked');
    expect(revocation.body.meta?.capability).toBe(token.id);

    const state = await gate.capabilityState(token.receipt);
    expect(state.revoked).toBe(true);
    expect(state.receipt?.id).toBe(revocation.id);

    await expect(
      gate.runWithCapability(token.receipt, 'notes.create', { text: 'x' })
    ).rejects.toMatchObject({ code: 'revoked-capability' });
    expect(calls).toEqual([]);
    expect((await gate.history('agent:planner')).at(-1)?.body.meta?.reason).toBe(
      'revoked-capability'
    );
  });

  it('cannot revoke a token it did not pin', async () => {
    const other = await notesGate({ keyId: 'issuer-b' });
    const token = await other.gate.issueCapability({
      subject: 'agent:planner',
      scopes: ['notes:write'],
      expiresAt: 1_700_000_060_000,
    });
    const local = await notesGate();
    await expect(local.gate.revokeCapability(token.receipt)).rejects.toMatchObject({
      code: 'foreign-issuer',
    });
  });

  it('keeps one chain per subject even when two tokens run in parallel', async () => {
    const { gate } = await notesGate();
    const token = await gate.issueCapability({
      subject: 'agent:planner',
      scopes: ['notes:read'],
      expiresAt: 1_700_000_060_000,
    });
    await Promise.all([
      gate.runWithCapability(token.receipt, 'notes.read'),
      gate.runWithCapability(token.receipt, 'notes.read'),
      gate.runWithCapability(token.receipt, 'notes.read'),
    ]);
    const history = await gate.verifyHistory('agent:planner');
    expect(history.count).toBe(6);
    expect(history.head).toBe(history.receipts.at(-1)?.id);
  });

  it('rejects a token with garbage rather than treating it as absent', async () => {
    const { gate } = await notesGate();
    for (const bad of [undefined, null, 'token', 42, {}, { v: 1 }]) {
      await expect(gate.runWithCapability(bad, 'notes.read')).rejects.toMatchObject({
        code: 'invalid-capability',
      });
    }
    expect((await gate.history('agent:unverified')).length).toBeGreaterThan(0);
  });
});
