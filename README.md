# sovereign-agents

Receipt-first action gate for Sovereign OS agents. An agent cannot touch data without leaving evidence: `run()` seals an Ed25519-signed `agent.action.requested` receipt into the vault **before** the handler is invoked, then appends `completed` or `failed` to the same per-actor hash chain. If that first receipt cannot be written, the handler never runs.

Deny-by-default, fail-closed, no cloud, no account, no network. An auditor verifies the whole history offline from the receipts alone.

## Install

```bash
npm install sovereign-agents sovereign-attest sovereign-vault
```

Sovereign OS ships it as plain ESM for Node 20+.

## Use

```ts
import { MemoryBlobStore, Vault, randomBytes } from 'sovereign-vault';
import { AgentGate, AgentsError } from 'sovereign-agents';

const vault = await Vault.open({ store: new MemoryBlobStore(), masterKey: randomBytes(32) });
const gate = await AgentGate.open({ vault, keyId: 'agent-gate' });

gate.register<{ text: string }>(
  'notes.create',
  async (args, context) => {
    // context.receiptId already exists on disk: the claim precedes the effect.
    return notes.insert(args.text);
  },
  { scopes: ['notes:write'], mutating: true, description: 'Create one note' }
);

const planner = { id: 'agent:planner', scopes: ['notes:write'] };
const { value, receipts } = await gate.run(planner, 'notes.create', { text: 'self-hosted' });

const report = await gate.verifyHistory(planner.id); // every signature and prev link checked
```

Nothing outside the registry can ever run, and an action cannot be silently redefined — a second `register()` for the same name throws.

## What the gate guarantees

| Guarantee            | How                                                                                                                                                                |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Deny-by-default      | The allow-list is the registry. An unknown action is refused _and_ receipted as `agent.action.denied`; the handler is never called                                 |
| Receipt before data  | The `requested` receipt is sealed and persisted first. A store failure aborts with `receipt-required` and the handler does not run (fail closed)                   |
| Every verdict logged | Denials of a missing scope record exactly which scopes were missing, so a policy change is auditable                                                               |
| Data minimisation    | Arguments and results are stored **only as sha256 digests**. Receipts are safe to publish; no plaintext payload, no secret, no PII lands in the vault              |
| One chain per actor  | Each actor's stream is `sha256(canonical({ kind: 'sovereign-agents/actor', v: 1, id }))`, and `run()` serialises per actor so parallel calls cannot fork it        |
| Tamper evidence      | Receipts are signed by a key that lives in [`sovereign-vault`](https://github.com/krisakornutama/sovereign-vault); rewriting or deleting one breaks the chain walk |
| Rollback evidence    | `anchor()` records the vault root in an append-only log; `checkAnchor()` fails once history has been truncated                                                     |
| Verifiable elsewhere | `verify(receipt)` and `verifyHistory(actor)` work from receipts alone, with the pinned key — no registry, no gate, no network                                      |

Failure semantics are part of the contract, not an afterthought: a handler that throws becomes `handler-failed` **with a `failed` receipt already written**, and its `cause` is preserved. Only the error _code_ is receipted — never the message, which could carry a secret.

## What a receipt looks like

```json
{
  "action": "agent.action.requested",
  "actor": "agent:planner",
  "artifact": { "name": "agent-action:agent:planner", "sha256": "<actor stream digest>" },
  "at": 1731400000000,
  "prev": "<id of the previous receipt for this actor>",
  "meta": {
    "action": "notes.create",
    "request": "<sha256 of the canonical arguments>",
    "mutating": "true",
    "scopes": "notes:write"
  }
}
```

The body above is signed and wrapped by `sovereign-attest`; `id` is the sha256 of the canonical body and doubles as the vault path. Because `meta` holds digests only, two operators can diff histories without ever exchanging the data the agent touched.

## API

| Export                                               | What it does                                                                                                                                       |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AgentGate.open({ vault, keyId?, now?, onDenied? })` | Loads or creates the signing key inside the vault and returns the gate                                                                             |
| `gate.register(name, handler, policy?)`              | Adds one action to the allow-list; `policy` is `{ scopes?, mutating?, description? }`                                                              |
| `gate.run(principal, action, args?)`                 | Policy check → `requested` receipt → handler → `completed`/`failed` receipt                                                                        |
| `gate.actions()`                                     | The sorted allow-list — what this gate is willing to do at all                                                                                     |
| `gate.history(actor)` / `gate.verifyHistory(actor)`  | Verified chain for one actor, oldest first, plus head and count                                                                                    |
| `gate.verify(receipt)`                               | Verifies one receipt from the wire against the gate's pinned key                                                                                   |
| `gate.anchor(log)` / `gate.checkAnchor(log)`         | Anchors the vault root and later detects rollback of old history                                                                                   |
| `AgentsError` codes                                  | `invalid-principal`, `invalid-action`, `unknown-action`, `missing-scope`, `duplicate-action`, `invalid-args`, `receipt-required`, `handler-failed` |

`onDenied` gives an operator a live hook (alerting, metrics). A throwing observer cannot change the verdict.

## Limitations (deliberate, milestone 1)

- **One writer per vault.** The gate serialises chains _inside one process_; two processes writing the same vault can interleave heads. Cross-process sequencing arrives with `sovereign-fabric`.
- **Policy is static.** Scopes are declared at `register()` time. Delegation, expiry and per-tenant policy need a policy source that is itself receipted.
- **Evidence, not prevention.** The gate proves what ran; it cannot stop a component that bypasses it. Modules that mutate data must be reachable only through the gate for the guarantee to bite — that is an architecture rule, not a library feature.
- **Rollback needs an anchor.** History is only provably complete once `anchor()` published the root somewhere the attacker cannot rewrite. Inside the same vault, a deleted tail looks like a shorter but valid history.
- **Digests are not payloads.** A receipt proves _which_ request ran, not what it contained. Reproducing an action needs the data from elsewhere.
- **Key compromise is not recoverable by the chain.** Rotate (`sovereign-attest` rotation statements) and pin the new key; receipts signed by a stolen key stay valid to anyone who trusts that key.

## Scripts

```bash
npm run lint && npm run typecheck && npm run format:check
npm run test:coverage   # gate: 90 statements / 80 branches / 90 functions / 90 lines
npm run build
npm run example         # end-to-end demo against the real vault: allow, deny, verify
```

MIT.
