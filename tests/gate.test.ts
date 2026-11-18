import { describe, expect, it } from 'vitest';
import { MemoryAnchorLog } from 'sovereign-vault';
import { loadReceipt, type Receipt } from 'sovereign-attest';
import {
  ACTION_COMPLETED,
  ACTION_DENIED,
  ACTION_FAILED,
  ACTION_REQUESTED,
  AgentGate,
  AgentsError,
  type DenialRecord,
} from '../src/index.js';
import { makeGate } from './helpers.js';

const planner = (scopes: readonly string[] = ['notes:write']) => ({
  id: 'agent:planner',
  scopes,
});

async function expectAgentsError(promise: Promise<unknown>, code: string): Promise<AgentsError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(AgentsError);
    const agentsError = error as AgentsError;
    expect(agentsError.code).toBe(code);
    return agentsError;
  }
  throw new Error(`expected AgentsError(${code}) but the call resolved`);
}

describe('deny-by-default', () => {
  it('rejects an unknown action and still receipts the denial', async () => {
    const { gate } = await makeGate();
    const error = await expectAgentsError(
      gate.run(planner(), 'notes.delete', { id: 'n1' }),
      'unknown-action'
    );
    expect(error.receiptId).toBeUndefined();

    const history = await gate.history('agent:planner');
    expect(history).toHaveLength(1);
    expect(history[0]?.body.action).toBe(ACTION_DENIED);
    expect(history[0]?.body.meta?.reason).toBe('unknown-action');
    expect(history[0]?.body.meta?.action).toBe('notes.delete');
    expect(history[0]?.body.meta?.request).toMatch(/^[0-9a-f]{64}$/);
  });

  it('rejects a missing scope and records which scopes were missing', async () => {
    const { gate } = await makeGate();
    gate.register('notes.create', () => null, { scopes: ['notes:write', 'notes:publish'] });
    await expectAgentsError(
      gate.run(planner(['notes:write']), 'notes.create', {}),
      'missing-scope'
    );

    const history = await gate.history('agent:planner');
    expect(history).toHaveLength(1);
    expect(history[0]?.body.action).toBe(ACTION_DENIED);
    expect(history[0]?.body.meta?.missingScopes).toBe('notes:publish');
  });

  it('never calls the handler for a denial', async () => {
    const { gate } = await makeGate();
    let calls = 0;
    gate.register(
      'notes.create',
      () => {
        calls += 1;
        return null;
      },
      { scopes: ['notes:write'] }
    );
    await expectAgentsError(gate.run(planner([]), 'notes.create', {}), 'missing-scope');
    await expectAgentsError(gate.run(planner(), 'notes.unknown', {}), 'unknown-action');
    expect(calls).toBe(0);
  });

  it('notifies an observer, and a throwing observer cannot change the verdict', async () => {
    const seen: DenialRecord[] = [];
    const { gate } = await makeGate({
      onDenied: (record) => {
        seen.push(record);
        throw new Error('observer exploded');
      },
    });
    await expectAgentsError(gate.run(planner(), 'notes.absent', {}), 'unknown-action');
    expect(seen).toHaveLength(1);
    expect(seen[0]?.reason).toBe('unknown-action');
    expect(seen[0]?.receipt.body.action).toBe(ACTION_DENIED);
  });
});

describe('receipt before data', () => {
  it('seals the requested receipt before the handler runs', async () => {
    const { gate, vault } = await makeGate();
    const seen: { receipt: Receipt | null } = { receipt: null };
    gate.register<{ text: string }>(
      'notes.create',
      async (args, context) => {
        seen.receipt = await loadReceipt(vault, context.receiptId);
        return { id: 'note-1', text: args.text };
      },
      { scopes: ['notes:write'], mutating: true }
    );

    const result = await gate.run<{ id: string; text: string }>(planner(), 'notes.create', {
      text: 'hello',
    });

    expect(seen.receipt).not.toBeNull();
    expect(seen.receipt?.body.action).toBe(ACTION_REQUESTED);
    expect(seen.receipt?.id).toBe(result.receipts.requested.id);
    expect(result.receipts.requested.body.meta?.mutating).toBe('true');
    expect(result.receipts.completed.body.action).toBe(ACTION_COMPLETED);
    expect(result.receipts.completed.body.meta?.request).toBe(result.receipts.requested.id);
    expect(result.receipts.completed.body.meta?.result).toMatch(/^[0-9a-f]{64}$/);
    expect(result.receipts.completed.body.meta?.durationMs).toMatch(/^\d+$/);
  });

  it('does not run the handler when the pre-action receipt cannot be written', async () => {
    const { gate, faults } = await makeGate();
    let calls = 0;
    gate.register('notes.create', () => {
      calls += 1;
      return 'ok';
    });
    faults.failPut = (key) => key.startsWith('attest/receipts/');

    await expectAgentsError(gate.run(planner(), 'notes.create', {}), 'receipt-required');
    expect(calls).toBe(0);
    expect(await gate.history('agent:planner')).toHaveLength(0);
  });

  it('surfaces an unsealed outcome instead of returning an unverified result', async () => {
    const { gate, faults } = await makeGate();
    let writes = 0;
    faults.failPut = (key) => {
      if (!key.startsWith('attest/receipts/')) return false;
      writes += 1;
      return writes > 1;
    };
    gate.register('notes.create', () => 'written');

    const error = await expectAgentsError(
      gate.run(planner(), 'notes.create', {}),
      'receipt-required'
    );
    expect(error.receiptId).toMatch(/^[0-9a-f]{64}$/);

    faults.failPut = null;
    const history = await gate.history('agent:planner');
    expect(history).toHaveLength(1);
    expect(history[0]?.body.action).toBe(ACTION_REQUESTED);
  });

  it('refuses to let a denial pass without evidence when its receipt fails', async () => {
    const { gate, faults } = await makeGate();
    faults.failPut = (key) => key.startsWith('attest/receipts/');
    await expectAgentsError(gate.run(planner(), 'notes.absent', {}), 'receipt-required');
  });

  it('keeps one sequential chain per actor even under parallel calls', async () => {
    const { gate } = await makeGate();
    gate.register('notes.read', () => 'ok');
    await Promise.all([
      gate.run(planner(), 'notes.read', { n: 1 }),
      gate.run(planner(), 'notes.read', { n: 2 }),
      gate.run(planner(), 'notes.read', { n: 3 }),
    ]);

    const report = await gate.verifyHistory('agent:planner');
    expect(report.count).toBe(6);
    expect(report.receipts[0]?.body.prev).toBeNull();
    for (let index = 1; index < report.receipts.length; index += 1) {
      expect(report.receipts[index]?.body.prev).toBe(report.receipts[index - 1]?.id);
    }
    expect(new Set(report.receipts.map((receipt) => receipt.id)).size).toBe(6);
  });
});

describe('outcomes', () => {
  it('receipts a handler failure and preserves the original cause', async () => {
    const { gate } = await makeGate();
    const boom = Object.assign(new Error('disk on fire'), { code: 'E_IO' });
    gate.register('notes.create', () => {
      throw boom;
    });

    const error = await expectAgentsError(
      gate.run(planner(), 'notes.create', { text: 'x' }),
      'handler-failed'
    );
    expect(error.cause).toBe(boom);
    expect(error.receiptId).toMatch(/^[0-9a-f]{64}$/);

    const history = await gate.history('agent:planner');
    expect(history.at(-1)?.body.action).toBe(ACTION_FAILED);
    expect(history.at(-1)?.body.meta?.error).toBe('E_IO');
    expect(history.at(-1)?.id).toBe(error.receiptId);
  });

  it('normalises unknown error shapes instead of leaking messages', async () => {
    const { gate } = await makeGate();
    gate.register('notes.create', () => {
      throw new Error('secret=do-not-store');
    });
    const error = await expectAgentsError(
      gate.run(planner(), 'notes.create', {}),
      'handler-failed'
    );
    const history = await gate.history('agent:planner');
    expect(history.at(-1)?.body.meta?.error).toBe('error');
    expect(JSON.stringify(history)).not.toContain('do-not-store');
    expect(error.receiptId).toBe(history.at(-1)?.id);
  });

  it('marks an unserialisable result as unavailable rather than hiding the receipt', async () => {
    const { gate } = await makeGate();
    gate.register('notes.create', () => () => 1);
    const result = await gate.run(planner(), 'notes.create', {});
    expect(result.receipts.completed.body.meta?.result).toBe('unavailable');
  });
});

describe('data minimisation', () => {
  it('stores only digests, never arguments', async () => {
    const { gate } = await makeGate();
    gate.register('notes.create', () => 'ok');
    const result = await gate.run(planner(), 'notes.create', {
      password: 's3cret-value',
      text: 'private note',
    });

    const serialised = JSON.stringify(result.receipts);
    expect(serialised).not.toContain('s3cret-value');
    expect(serialised).not.toContain('private note');
    expect(result.receipts.requested.body.meta?.request).toMatch(/^[0-9a-f]{64}$/);
  });

  it('rejects arguments that cannot be canonically digested, before any receipt', async () => {
    const { gate } = await makeGate();
    gate.register('notes.create', () => 'ok');
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;

    await expectAgentsError(
      gate.run(planner(), 'notes.create', () => 1),
      'invalid-args'
    );
    await expectAgentsError(gate.run(planner(), 'notes.create', { big: 1n }), 'invalid-args');
    await expectAgentsError(gate.run(planner(), 'notes.create', cyclic), 'invalid-args');
    expect(await gate.history('agent:planner')).toHaveLength(0);
  });
});

describe('rejections before any side effect', () => {
  it('rejects malformed principals and action names without writing receipts', async () => {
    const { gate } = await makeGate();
    gate.register('notes.create', () => 'ok');
    await expectAgentsError(gate.run({ id: '' }, 'notes.create', {}), 'invalid-principal');
    await expectAgentsError(gate.run(planner(), 'Notes Create', {}), 'invalid-action');
    expect(await gate.history('agent:planner')).toHaveLength(0);
  });

  it('refuses to open without a usable vault', async () => {
    await expectAgentsError(AgentGate.open({ vault: {} as never }), 'receipt-required');
  });

  it('rejects an invalid actor when reading history', async () => {
    const { gate } = await makeGate();
    await expectAgentsError(gate.history(''), 'invalid-principal');
  });
});

describe('verification', () => {
  it('verifies a receipt from the wire without the registry', async () => {
    const { gate } = await makeGate();
    gate.register('notes.create', () => 'ok');
    await gate.run(planner(), 'notes.create', {});
    const [receipt] = await gate.history('agent:planner');
    expect(gate.verify(receipt).action).toBe(ACTION_REQUESTED);
  });

  it('anchors the vault root and checks it later', async () => {
    const { gate } = await makeGate();
    gate.register('notes.create', () => 'ok');
    await gate.run(planner(), 'notes.create', {});
    const log = new MemoryAnchorLog();

    const report = (await gate.anchor(log)) as { root: string };
    expect(report.root).toMatch(/^[0-9a-f]{64}$/);
    await expect(gate.checkAnchor(log)).resolves.toBeDefined();
  });
});
