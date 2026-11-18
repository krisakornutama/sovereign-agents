import {
  Attest,
  type AnchorLogLike,
  type AttestVault,
  type Receipt,
  type ReceiptBody,
} from 'sovereign-attest';
import {
  CAPABILITY_ISSUED,
  CAPABILITY_REVOKED,
  assertCapabilityLive,
  capabilityStream,
  grantMeta,
  missingScopes,
  normaliseGrant,
  openCapability,
  type Capability,
  type CapabilityGrant,
} from './capability.js';
import { AgentsError } from './errors.js';
import {
  assertActionName,
  assertActorId,
  assertPrincipal,
  digestOf,
  streamOf,
  type Principal,
} from './names.js';
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
  /**
   * Extra keys allowed to issue capability tokens (`keyId` → pinned public key).
   * The gate's own key is always accepted; anything else must be pinned here, so a
   * token cannot appoint its own issuer.
   */
  readonly capabilityIssuers?: Readonly<Record<string, string>>;
  /** Actor name written into capability receipts. Defaults to `agent:issuer`. */
  readonly issuer?: string;
}

export type DenialReason =
  | 'unknown-action'
  | 'missing-scope'
  | 'out-of-scope-action'
  | 'invalid-capability'
  | 'foreign-issuer'
  | 'capability-not-yet-valid'
  | 'expired-capability'
  | 'revoked-capability';

export interface DenialRecord {
  readonly actor: string;
  readonly action: string;
  readonly reason: DenialReason;
  readonly receipt: Receipt;
}

export interface CapabilityState {
  readonly revoked: boolean;
  /** When the revocation was recorded, or null while the token is still live. */
  readonly at: number | null;
  readonly receipt: Receipt | null;
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

/** Best-effort actor for a token that may not verify; never used for a decision. */
function claimedSubject(token: unknown): string {
  if (typeof token !== 'object' || token === null) return 'agent:unverified';
  const body = (token as { readonly body?: unknown }).body;
  if (typeof body !== 'object' || body === null) return 'agent:unverified';
  const meta = (body as { readonly meta?: unknown }).meta;
  if (typeof meta !== 'object' || meta === null) return 'agent:unverified';
  try {
    return assertActorId((meta as { readonly subject?: unknown }).subject);
  } catch {
    return 'agent:unverified';
  }
}

/**
 * Receipt-first gate for agent actions.
 *
 * `run()` seals a signed `agent.action.requested` receipt **before** invoking the
 * handler, then appends `completed`/`failed`. If the pre-action receipt cannot
 * be written the handler is never called (fail closed). Arguments and results
 * are stored only as digests, so receipts are safe to publish and reproduce.
 *
 * `runWithCapability()` is the same path with the permissions moved out of the
 * caller's mouth: the actor and its scopes come from a signed capability receipt
 * that the gate verifies (issuer pin, validity window, revocation) first.
 */
export class AgentGate {
  private readonly attest: Attest;
  private readonly clock: () => number;
  private readonly options: GateOptions;
  private readonly registry = new ActionRegistry();
  private readonly chains = new Map<string, Promise<void>>();
  private readonly issuers: Readonly<Record<string, string>>;
  private readonly issuerId: string;

  private constructor(options: GateOptions, attest: Attest) {
    this.options = options;
    this.attest = attest;
    this.clock = options.now ?? Date.now;
    this.issuers = { [attest.keyId]: attest.publicKey, ...options.capabilityIssuers };
    this.issuerId = assertActorId(options.issuer ?? 'agent:issuer');
  }

  static async open(options: GateOptions): Promise<AgentGate> {
    const raw = options as GateOptions | null | undefined;
    const vault = raw?.vault as AttestVault | null | undefined;
    if (!vault || typeof vault.get !== 'function' || typeof vault.put !== 'function') {
      throw new AgentsError('receipt-required', 'AgentGate.open needs a vault with get/put');
    }
    if (raw?.issuer !== undefined) assertActorId(raw.issuer);
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

  /** Label of the key that signs this gate's receipts and capability tokens. */
  get keyId(): string {
    return this.attest.keyId;
  }

  /** Public half of that key, for pinning it elsewhere. */
  get publicKey(): string {
    return this.attest.publicKey;
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

  /**
   * Seals a capability token for `subject`. The token is the signed receipt, so it
   * can be handed to another process and verified offline against the pinned issuers.
   */
  async issueCapability(grantInput: unknown): Promise<Capability> {
    const grant: CapabilityGrant = normaliseGrant(grantInput);
    const receipt = await this.sealOrThrow(CAPABILITY_ISSUED, this.issuerId, grantMeta(grant), {
      name: `agent-capability:${grant.subject}`,
      sha256: digestOf(grant),
    });
    return openCapability(receipt, { trustedKeys: this.issuers });
  }

  /** Verifies a token with the pinned issuer keys and returns what it grants. */
  verifyCapability(token: unknown): Capability {
    try {
      return openCapability(token, { trustedKeys: this.issuers });
    } catch (error) {
      if (error instanceof AgentsError) throw error;
      if (errorCodeOf(error) === 'unknown-key') {
        throw new AgentsError(
          'foreign-issuer',
          'capability was not signed by a pinned issuer; it grants nothing here',
          { cause: error }
        );
      }
      throw new AgentsError('invalid-capability', 'capability token is not a valid signed grant', {
        cause: error,
      });
    }
  }

  /** Revokes a token. The revocation is a receipt, so the decision is auditable later. */
  async revokeCapability(token: unknown, reason?: string): Promise<Receipt> {
    const capability = this.verifyCapability(token);
    const stream = capabilityStream(capability.id);
    return this.sealOrThrow(
      CAPABILITY_REVOKED,
      this.issuerId,
      {
        capability: capability.id,
        ...(reason === undefined ? {} : { reason }),
      },
      { name: `agent-capability:${capability.id}`, sha256: stream }
    );
  }

  /** Is this token revoked? Reads and verifies the token's own revocation chain. */
  async capabilityState(token: unknown): Promise<CapabilityState> {
    const capability = this.verifyCapability(token);
    const report = await this.attest.provenance(capabilityStream(capability.id));
    const last = report.receipts.at(-1);
    if (!last || last.body.action !== CAPABILITY_REVOKED) {
      return { revoked: false, at: null, receipt: null };
    }
    return { revoked: true, at: last.body.at, receipt: last };
  }

  async run<T = unknown>(
    principal: unknown,
    action: unknown,
    args?: unknown
  ): Promise<RunResult<T>> {
    const who = assertPrincipal(principal);
    const name = assertActionName(action);
    const requestDigest = this.requestDigestOf(args);

    // One chain per actor: parallel calls must not fork the hash chain.
    return this.enqueue(who.id, () => this.execute<T>(who, name, args, requestDigest));
  }

  /**
   * Capability path: the caller presents a signed token instead of asserting scopes.
   * The token decides who acts and what is allowed, so a caller cannot widen either
   * — and every refusal is receipted before it is thrown.
   */
  async runWithCapability<T = unknown>(
    token: unknown,
    action: unknown,
    args?: unknown
  ): Promise<RunResult<T>> {
    const name = assertActionName(action);
    const requestDigest = this.requestDigestOf(args);
    const subject = claimedSubject(token);

    return this.enqueue(subject, async () => {
      let capability: Capability;
      try {
        capability = this.verifyCapability(token);
      } catch (error) {
        const reason: DenialReason =
          errorCodeOf(error) === 'foreign-issuer' ? 'foreign-issuer' : 'invalid-capability';
        await this.recordDenial(subject, name, requestDigest, reason, [], { reason });
        throw error instanceof AgentsError
          ? error
          : new AgentsError('invalid-capability', 'capability token could not be verified', {
              cause: error,
            });
      }

      try {
        assertCapabilityLive(capability, this.clock());
      } catch (error) {
        await this.recordDenial(subject, name, requestDigest, 'expired-capability', [], {
          capability: capability.id,
        });
        throw error;
      }

      const state = await this.capabilityState(capability.receipt);
      if (state.revoked) {
        await this.recordDenial(subject, name, requestDigest, 'revoked-capability', [], {
          capability: capability.id,
        });
        throw new AgentsError(
          'revoked-capability',
          `capability ${capability.id} was revoked at ${state.at ?? 0}; nothing ran`
        );
      }

      if (capability.actions !== null && !capability.actions.includes(name)) {
        await this.recordDenial(subject, name, requestDigest, 'out-of-scope-action', [], {
          capability: capability.id,
          grantedActions: capability.actions.join(','),
        });
        throw new AgentsError(
          'missing-scope',
          `capability ${capability.id} is limited to ${capability.actions.join(', ')}; nothing ran`
        );
      }

      const required = this.registry.get(name)?.policy.scopes ?? [];
      const missing = missingScopes(capability, required);
      if (missing.length > 0) {
        await this.recordDenial(subject, name, requestDigest, 'missing-scope', missing, {
          capability: capability.id,
        });
        throw new AgentsError(
          'missing-scope',
          `capability ${capability.id} lacks ${missing.join(', ')}; nothing ran`
        );
      }

      return this.execute<T>(
        { id: subject, scopes: capability.scopes },
        name,
        args,
        requestDigest,
        { capability: capability.id }
      );
    });
  }

  private requestDigestOf(args: unknown): string {
    try {
      return digestOf(args);
    } catch (error) {
      throw new AgentsError(
        'invalid-args',
        'action arguments must be JSON-serialisable so they can be receipted by digest',
        { cause: error }
      );
    }
  }

  /** Policy check → `requested` receipt → handler → `completed`/`failed` receipt. */
  private async execute<T>(
    who: Principal,
    name: string,
    args: unknown,
    requestDigest: string,
    extraMeta: Readonly<Record<string, string | number>> = {}
  ): Promise<RunResult<T>> {
    const registered = this.registry.get(name);
    if (!registered) {
      await this.recordDenial(who.id, name, requestDigest, 'unknown-action', [], extraMeta);
      throw new AgentsError('unknown-action', `action "${name}" is not registered; nothing ran`);
    }

    const required = registered.policy.scopes ?? [];
    const granted = new Set(who.scopes);
    const missing = required.filter((scope) => !granted.has(scope));
    if (missing.length > 0) {
      await this.recordDenial(who.id, name, requestDigest, 'missing-scope', missing, extraMeta);
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
      ...extraMeta,
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
  }

  private elapsed(startedAt: number): string {
    return String(Math.max(0, this.clock() - startedAt));
  }

  private async seal(
    action: string,
    actor: string,
    meta: Readonly<Record<string, string | number>>,
    artifact: { readonly name: string; readonly sha256: string } = {
      name: `agent-action:${actor}`,
      sha256: streamOf(actor),
    }
  ): Promise<Receipt> {
    return this.attest.record({ action, actor, artifact, meta });
  }

  private async sealOrThrow(
    action: string,
    actor: string,
    meta: Readonly<Record<string, string | number>>,
    artifact?: { readonly name: string; readonly sha256: string }
  ): Promise<Receipt> {
    try {
      return await this.seal(action, actor, meta, artifact);
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
    meta: Readonly<Record<string, string | number>>
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
    reason: DenialReason,
    missing: readonly string[],
    detail: Readonly<Record<string, string | number>> = {}
  ): Promise<void> {
    let receipt: Receipt;
    try {
      receipt = await this.seal(ACTION_DENIED, actor, {
        action,
        request: requestDigest,
        reason,
        ...(missing.length === 0 ? {} : { missingScopes: missing.join(',') }),
        ...detail,
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
