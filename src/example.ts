/**
 * CLI demo: a receipt is written before the handler touches anything, and a
 * denied action still leaves evidence. Run with `npm run example`.
 */
import { MemoryBlobStore, Vault, randomBytes } from 'sovereign-vault';
import type { AgentsError } from './errors.js';
import { AgentGate } from './gate.js';

const vault = await Vault.open({
  store: new MemoryBlobStore(),
  masterKey: randomBytes(32),
});
const gate = await AgentGate.open({ vault, keyId: 'agent-gate' });

gate.register<{ text: string }>(
  'notes.create',
  (args, context) => {
    // The receipt already exists here; data is touched only after this point.
    console.log(`  handler running; pre-action receipt ${context.receiptId.slice(0, 12)}…`);
    return { id: 'note-1', text: args.text };
  },
  { scopes: ['notes:write'], mutating: true, description: 'Create one note' }
);

gate.register('notes.read', () => [], { scopes: ['notes:read'] });

const planner = { id: 'agent:planner', scopes: ['notes:write'] };

const created = await gate.run<{ id: string; text: string }>(planner, 'notes.create', {
  text: 'self-hosted notes',
});
console.log('created:', created.value);
console.log(
  'request → outcome:',
  created.receipts.requested.id.slice(0, 8),
  '→',
  created.receipts.completed.id.slice(0, 8)
);

try {
  await gate.run(planner, 'notes.delete', { id: created.value.id });
} catch (error) {
  const agentsError = error as AgentsError;
  console.log('denied:', agentsError.code, '· receipt:', agentsError.message);
}

// Capability path: the same gate, but the permissions arrive signed and expiring.
const token = await gate.issueCapability({
  subject: planner.id,
  scopes: ['notes:write'],
  expiresAt: Date.now() + 15 * 60_000,
});
console.log('token:', token.id.slice(0, 12) + '…', 'scopes:', token.scopes.join(','));

try {
  await gate.runWithCapability(token.receipt, 'notes.read');
} catch (error) {
  console.log('out of scope:', (error as AgentsError).code, '·', (error as AgentsError).message);
}

await gate.revokeCapability(token.receipt, 'demo rotation');
try {
  await gate.runWithCapability(token.receipt, 'notes.create', { text: 'after revoke' });
} catch (error) {
  console.log('revoked:', (error as AgentsError).code);
}

const report = await gate.verifyHistory(planner.id);
console.log(`verified ${report.count} receipts for ${report.actor}`);
for (const receipt of report.receipts) {
  console.log(` ${receipt.body.action.padEnd(24)} ${receipt.id.slice(0, 12)}…`);
}
