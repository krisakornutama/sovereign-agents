import { describe, expect, it } from 'vitest';
import { MemoryAnchorLog } from 'sovereign-vault';
import { Attest, receiptPath, saveHead, utf8, type Receipt } from 'sovereign-attest';
import { ACTION_COMPLETED, ACTION_DENIED, ACTION_REQUESTED, streamOf } from '../src/index.js';
import { makeGate } from './helpers.js';

const planner = { id: 'agent:planner', scopes: ['notes:write'] };

async function seed(gate: Awaited<ReturnType<typeof makeGate>>['gate']) {
  gate.register('notes.create', (args) => ({ echoed: args }), {
    scopes: ['notes:write'],
    mutating: true,
  });
  await gate.run(planner, 'notes.create', { text: 'one' });
  await gate.run(planner, 'notes.create', { text: 'two' });
  return gate.history('agent:planner');
}

describe('the chain', () => {
  it('links request → outcome → next request', async () => {
    const { gate } = await makeGate();
    const history = await seed(gate);
    expect(history).toHaveLength(4);
    expect(history.map((receipt) => receipt.body.action)).toEqual([
      ACTION_REQUESTED,
      ACTION_COMPLETED,
      ACTION_REQUESTED,
      ACTION_COMPLETED,
    ]);
    for (let index = 1; index < history.length; index += 1) {
      expect(history[index]?.body.prev).toBe(history[index - 1]?.id);
    }
    expect(history[0]?.body.prev).toBeNull();
  });

  it('records a denial in the same chain as allowed actions', async () => {
    const { gate } = await makeGate();
    await seed(gate);
    await gate.run(planner, 'notes.missing', {}).catch(() => undefined);
    const history = await gate.history('agent:planner');
    expect(history.at(-1)?.body.action).toBe(ACTION_DENIED);
    expect(history.at(-1)?.body.prev).toBe(history.at(-2)?.id);
  });
});

describe('tamper evidence', () => {
  it('rejects a receipt whose body was rewritten', async () => {
    const { gate, vault } = await makeGate();
    const history = await seed(gate);
    const original = history[1] as Receipt;
    const tampered = {
      ...original,
      body: { ...original.body, action: 'agent.action.planted' },
    };
    await vault.put(receiptPath(original.id), utf8(JSON.stringify(tampered)));

    await expect(gate.verifyHistory('agent:planner')).rejects.toThrow();
  });

  it('rejects a chain whose receipt was deleted', async () => {
    const { gate, vault } = await makeGate();
    const history = await seed(gate);
    const middle = history[1] as Receipt;
    await vault.delete(receiptPath(middle.id));

    await expect(gate.verifyHistory('agent:planner')).rejects.toThrow();
  });

  it('treats a receipt signed by another vault as untrusted', async () => {
    const first = await makeGate();
    first.gate.register('notes.create', () => 'ok', { scopes: ['notes:write'] });
    await first.gate.run(planner, 'notes.create', {});

    const second = await makeGate();
    second.gate.register('notes.create', () => 'ok', { scopes: ['notes:write'] });
    const foreign = await second.gate.run(planner, 'notes.create', {});

    expect(() => first.gate.verify(foreign.receipts.requested)).toThrow();
    // The foreign receipt is still self-verifying against its own pinned key.
    expect(second.gate.verify(foreign.receipts.requested).action).toBe(ACTION_REQUESTED);
  });

  it('detects a rolled-back head once the root was anchored', async () => {
    const { gate, vault } = await makeGate();
    const history = await seed(gate);
    const log = new MemoryAnchorLog();
    await gate.anchor(log);

    // Roll the stream back to the third receipt: a clean-looking shorter history.
    const third = history[2] as Receipt;
    await vault.delete(receiptPath((history[3] as Receipt).id));
    await saveHead(vault, streamOf('agent:planner'), third.id);

    const shortened = await gate.history('agent:planner');
    expect(shortened).toHaveLength(3);
    await expect(gate.checkAnchor(log)).rejects.toThrow();
  });
});

describe('receipts survive without the gate', () => {
  it('can be verified by a fresh Attest that trusts the same key', async () => {
    const { gate, vault } = await makeGate();
    const history = await seed(gate);
    const attest = await Attest.open({ vault, keyId: 'agent-gate' });
    expect(attest.verify(history[0]).actor).toBe('agent:planner');
  });
});
