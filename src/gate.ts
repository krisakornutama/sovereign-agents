import {
  Attest,
  type AnchorLogLike,
  type AttestVault,
  type Receipt,
  type ReceiptBody,
} from 'sovereign-attest';
import { AgentsError } from './errors.js';
import { assertActionName, assertActorId, assertPrincipal, digestOf, streamOf } from './names.js';
import { ActionRegistry, type ActionHandler, type ActionPolicy } from './policy.js';

/** The receipt that must exist before a handler runs. */
export const ACTION_REQUESTED = 'agent.action.requested';
export const ACTION_COMPLETED = 'agent.action.completed';
export const ACTION_FAILED = 'agent.action.failed';
export const ACTION_DENIED = 'agent.action.denied';

export interface GateOptions {
  /** Works with `sovereign-vault`'s `Vault` (or anything with the same shape). */
  readonly vault: AttestVault;
  readonly keyId?: string;
  /** Injectable clock for tests and replays. */
  readonly now?: () => number;
  /** Observer for denied attempts. Errors in the observer never change the verdict. */
  readonly onDenied?: (record: DenialRecord) => void;
}

export interface DenialRecord {
  readonly actor: string;
  readonly action: string;
  readonly reason: 'unknown-action' | 'missing-scope';
  readonly receipt: Receipt;
}

export interface RunResult<T> {
  readonly ok: true;
  readonly value: T;
  readonly receipts: {
    readonly requested: Receipt;
    readonly completed: Receipt;
  };
}

export interface HistoryReport {
  readonly actor: string;
  readonly stream: string;
  readonly head: string | null;
  /** Oldest first. Every signature and `prev` link was verified while reading. */
  readonly receipts: readonly Receipt[];
  readonly count: number;
}

function errorCodeOf(error: unknown): string {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    const code = (error as { readonly code?: unknown }).code;
    if (typeof code === 'string' && /^[A-Za-z0-9._-]{1,64}$/.test(code)) return code;
  }
  return 'error';
}

function safeDigest(value: unknown): string {
  try {
    return digestOf(value);
  } catch {
    // The action already ran; an unserialisable result must not hide the receipt.
    return 'unavailable';
  }
}

/**
 * Receipt-first gate for agent actions.
 *
 * `run()` seals a signed `agent.action.requested` receipt **before** invoking the
 * handler, then appends `completed`/`failed`. If the pre-action receipt cannot
 * be written the handler is never called (fail closed). Arguments and results
 * are stored only as digests, so receipts are safe to publish and reproduce.
 */
export class AgentGate {
  private readonly attest: Attest;
  private readonly clock: () => number;
  private readonly options: GateOptions;
  private readonly registry = new ActionRegistry();
  private readonly chains = new Map<string, Promise<void>>();

  private constructor(options: GateOptions, attest: Attest) {
    this.options = options;
    this.attest = attest;
    this.clock = options.now ?? Date.now;
  }

  static async open(options: GateOptions): Promise<AgentGate> {
    const raw = options as GateOptions | null | undefined;
    const vault = raw?.vault as AttestVault | null | undefined;
    if (!vault || typeof vault.get !== 'function' || typeof vault.put !== 'function') {
      throw new AgentsError('receipt-required', 'AgentGate.open needs a vault with get/put');
    }
    const now = raw?.now ?? Date.now;
    const attest = await Attest.open({
      vault,
      ...(raw?.keyId === undefined ? {} : { keyId: raw.keyId }),
      now,
    });
    return new AgentGate({ ...options, vault, now }, attest);
  }

  /** Registers an action. Re-registering the same name is an error, not a silent overwrite. */
  register<TArgs = unknown>(
    name: unknown,
    handler: ActionHandler<TArgs>,
    policy: ActionPolicy = {}
  ): this {
    this.registry.define(name, handler, policy);
    return this;
  }

  /** Sorted action names — the complete allow-list. */
  actions(): readonly string[] {
    return this.registry.names();
  }

  /** Verifies a receipt from disk or the wire against the gate's trusted keys. */
  verify(receipt: unknown): ReceiptBody {
    return this.attest.verify(receipt);
  }

  /** Verified receipt chain for one actor, oldest first. */
  async history(actor: unknown): Promise<readonly Receipt[]> {
    return (await this.verifyHistory(actor)).receipts;
  }

  async verifyHistory(actor: unknown): Promise<HistoryReport> {
    const id = assertActorId(actor);
    const tail = this.chains.get(id);
    if (tail) await tail;
    const stream = streamOf(id);
    const report = await this.attest.provenance(stream);
    return {
      actor: id,
      stream,
      head: report.head,
      receipts: report.receipts,
      count: report.receipts.length,
    };
  }

  /** Anchors the vault root into an append-only log (detects rollback of old history). */
  async anchor(log: AnchorLogLike): Promise<unknown> {
    return this.attest.anchor(log);
  }

  async checkAnchor(log: AnchorLogLike, expectedRoot?: string): Promise<unknown> {
    return this.attest.checkAnchor(log, expectedRoot);
  }

  async run<T = unknown>(
    principal: unknown,
    action: unknown,
    args?: unknown
  ): Promise<RunResult<T>> {
    const who = assertPrincipal(principal);
    const name = assertActionName(action);
    let requestDigest: string;
    try {
      requestDigest = digestOf(args);
    } catch (error) {
      throw new AgentsError(
        'invalid-args',
        'action arguments must be JSON-serialisable so they can be receipted by digest',
        { cause: error }
      );
    }

    // One chain per actor: parallel calls must not fork the hash chain.
    return this.enqueue(who.id, async () => {
      const registered = this.registry.get(name);
      if (!registered) {
        await this.recordDenial(who.id, name, requestDigest, 'unknown-action', []);
        throw new AgentsError('unknown-action', `action "${name}" is not registered; nothing ran`);
      }

      const required = registered.policy.scopes ?? [];
      const granted = new Set(who.scopes);
      const missing = required.filter((scope) => !granted.has(scope));
      if (missing.length > 0) {
        await this.recordDenial(who.id, name, requestDigest, 'missing-scope', missing);
        throw new AgentsError(
          'missing-scope',
          `principal "${who.id}" lacks ${missing.join(', ')}; nothing ran`
        );
      }

      const mutating = registered.policy.mutating === true;
      const requested = await this.sealOrThrow(ACTION_REQUESTED, who.id, {
        action: name,
        request: requestDigest,
        mutating: String(mutating),
        ...(required.length === 0 ? {} : { scopes: required.join(',') }),
      });

      const startedAt = this.clock();
      let value: unknown;
      try {
        value = await registered.handler(args, {
          actor: who.id,
          action: name,
          receiptId: requested.id,
          mutating,
        });
      } catch (error) {
        const failed = await this.sealOutcome(ACTION_FAILED, who.id, requested.id, {
          action: name,
          request: requested.id,
          durationMs: this.elapsed(startedAt),
          error: errorCodeOf(error),
        });
        throw new AgentsError(
          'handler-failed',
          `action "${name}" failed after its request was receipted as ${requested.id}`,
          { cause: error, receiptId: failed.id }
        );
      }

      const completed = await this.sealOutcome(ACTION_COMPLETED, who.id, requested.id, {
        action: name,
        request: requested.id,
        durationMs: this.elapsed(startedAt),
        result: safeDigest(value),
      });
      return { ok: true, value: value as T, receipts: { requested, completed } };
    });
  }

  private elapsed(startedAt: number): string {
    return String(Math.max(0, this.clock() - startedAt));
  }

  private async seal(
    action: string,
    actor: string,
    meta: Readonly<Record<string, string>>
  ): Promise<Receipt> {
    return this.attest.record({
      action,
      actor,
      artifact: { name: `agent-action:${actor}`, sha256: streamOf(actor) },
      meta,
    });
  }

  private async sealOrThrow(
    action: string,
    actor: string,
    meta: Readonly<Record<string, string>>
  ): Promise<Receipt> {
    try {
      return await this.seal(action, actor, meta);
    } catch (error) {
      throw new AgentsError(
        'receipt-required',
        'could not seal the pre-action receipt; the action was NOT executed',
        { cause: error }
      );
    }
  }

  private async sealOutcome(
    action: string,
    actor: string,
    requestedId: string,
    meta: Readonly<Record<string, string>>
  ): Promise<Receipt> {
    try {
      return await this.seal(action, actor, meta);
    } catch (error) {
      throw new AgentsError(
        'receipt-required',
        'the action ran but its outcome receipt could not be sealed — treat the result as unverified',
        { cause: error, receiptId: requestedId }
      );
    }
  }

  private async recordDenial(
    actor: string,
    action: string,
    requestDigest: string,
    reason: DenialRecord['reason'],
    missing: readonly string[]
  ): Promise<void> {
    let receipt: Receipt;
    try {
      receipt = await this.seal(ACTION_DENIED, actor, {
        action,
        request: requestDigest,
        reason,
        ...(missing.length === 0 ? {} : { missingScopes: missing.join(',') }),
      });
    } catch (error) {
      throw new AgentsError(
        'receipt-required',
        'could not seal the denial receipt; the decision stands but has no evidence',
        { cause: error }
      );
    }
    try {
      this.options.onDenied?.({ actor, action, reason, receipt });
    } catch {
      // An observer must never change the verdict or hide the denial.
    }
  }

  private enqueue<T>(key: string, task: () => Promise<T>): Promise<T> {
    const previous = this.chains.get(key) ?? Promise.resolve();
    const run = previous.then(task, task);
    this.chains.set(
      key,
      run.then(
        () => undefined,
        () => undefined
      )
    );
    return run;
  }
}
