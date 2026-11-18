import {
  canonicalJson,
  openReceipt,
  sha256Hex,
  type Receipt,
  type ReceiptBody,
  type ReceiptTrust,
} from 'sovereign-attest';
import { AgentsError } from './errors.js';
import { assertActionName, assertActorId, digestOf, normaliseScopes } from './names.js';

/**
 * Capability tokens
 *
 * A token is not a new format to trust: it *is* a `sovereign-attest` receipt, so a
 * token that survives `openReceipt` is one whose issuer really signed these scopes
 * for this subject. Nothing else in the system may invent permissions, and the
 * issuer list is a pin, not a claim from the token itself.
 */
export const CAPABILITY_ISSUED = 'agent.capability.issued';
export const CAPABILITY_REVOKED = 'agent.capability.revoked';

const MAX_ACTIONS = 64;
const SHA256 = /^[0-9a-f]{64}$/;

/** What an issuer grants. Everything here is signed into the receipt's `meta`. */
export interface CapabilityGrant {
  /** The actor the token is bound to. A token cannot be used to act as anyone else. */
  readonly subject: string;
  readonly scopes: readonly string[];
  /** Narrows the token to these actions even where the scopes would allow more. */
  readonly actions?: readonly string[];
  /** Unix ms lower bound; omitted means "valid from issuance". */
  readonly notBefore?: number;
  /** Unix ms upper bound. Required: a token that never expires is a password. */
  readonly expiresAt: number;
}

export interface Capability {
  /** Receipt id of the issuance claim: the token's identity in denial receipts. */
  readonly id: string;
  readonly issuer: string;
  readonly subject: string;
  readonly scopes: readonly string[];
  /** `null` means "any registered action the scopes allow". */
  readonly actions: readonly string[] | null;
  readonly notBefore: number;
  readonly expiresAt: number;
  readonly issuedAt: number;
  /** The signed token itself; portable and verifiable offline. */
  readonly receipt: Receipt;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isTime(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new AgentsError('invalid-capability', `${field} must be a non-negative integer (ms)`);
  }
  return value;
}

function normaliseActions(value: unknown): readonly string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) {
    throw new AgentsError('invalid-capability', 'capability.actions must be an array of names');
  }
  const actions: string[] = [];
  for (const entry of value) {
    const name = assertActionName(entry);
    if (!actions.includes(name)) actions.push(name);
  }
  if (actions.length > MAX_ACTIONS) {
    throw new AgentsError('invalid-capability', `capability.actions holds at most ${MAX_ACTIONS}`);
  }
  return actions;
}

/** Validates an issuer-supplied grant before anything is signed. */
export function normaliseGrant(value: unknown): CapabilityGrant {
  if (!isRecord(value)) {
    throw new AgentsError('invalid-capability', 'capability grant must be an object');
  }
  let subject: string;
  let scopes: readonly string[];
  let actions: readonly string[] | undefined;
  try {
    subject = assertActorId(value.subject);
    scopes = normaliseScopes(value.scopes, 'invalid-capability', 'capability.scopes');
    actions = normaliseActions(value.actions);
  } catch (error) {
    // One code for anything the issuer got wrong, so callers do not have to guess
    // whether a bad subject surfaces as a principal error or a capability error.
    throw new AgentsError(
      'invalid-capability',
      error instanceof Error ? error.message : 'capability grant is invalid',
      { cause: error }
    );
  }
  const notBefore = value.notBefore === undefined ? 0 : isTime(value.notBefore, 'notBefore');
  const expiresAt = isTime(value.expiresAt, 'expiresAt');
  if (expiresAt <= notBefore) {
    throw new AgentsError('invalid-capability', 'expiresAt must be later than notBefore');
  }
  return {
    subject,
    scopes,
    ...(actions === undefined ? {} : { actions }),
    ...(notBefore === 0 ? {} : { notBefore }),
    expiresAt,
  };
}

/** The vault stream a token's revocation statements are appended to. */
export function capabilityStream(tokenId: string): string {
  if (typeof tokenId !== 'string' || !SHA256.test(tokenId)) {
    throw new AgentsError('invalid-capability', 'capability id must be a lowercase hex sha256');
  }
  return sha256Hex(canonicalJson({ kind: 'sovereign-agents/capability', v: 1, id: tokenId }));
}

/** The `meta` an issuance receipt is sealed with: everything the token grants. */
export function grantMeta(grant: CapabilityGrant): Readonly<Record<string, string | number>> {
  return {
    subject: grant.subject,
    scopes: grant.scopes.join(','),
    ...(grant.actions === undefined ? {} : { actions: grant.actions.join(',') }),
    notBefore: grant.notBefore ?? 0,
    expiresAt: grant.expiresAt,
    grant: digestOf(grant),
  };
}

function splitList(value: unknown, field: string): string[] {
  if (value === undefined) return [];
  if (typeof value !== 'string') {
    throw new AgentsError('invalid-capability', `capability ${field} must be a string`);
  }
  return value.length === 0 ? [] : value.split(',');
}

function grantFromMeta(body: ReceiptBody): {
  grant: CapabilityGrant;
  issuedAt: number;
} {
  // A receipt from the wire is not a capability until its meta proves it, so the
  // fields are read as possibly missing rather than trusted from the type.
  const meta = body.meta as Record<string, string | number | undefined> | undefined;
  if (!meta || meta.subject === undefined || meta.expiresAt === undefined) {
    throw new AgentsError('invalid-capability', 'receipt is not a capability grant');
  }
  const grant = normaliseGrant({
    subject: meta.subject,
    scopes: splitList(meta.scopes, 'scopes'),
    ...(meta.actions === undefined ? {} : { actions: splitList(meta.actions, 'actions') }),
    ...(meta.notBefore === undefined ? {} : { notBefore: meta.notBefore }),
    expiresAt: meta.expiresAt,
  });
  if (meta.grant !== undefined && meta.grant !== digestOf(grant)) {
    throw new AgentsError('invalid-capability', 'capability meta does not match its grant digest');
  }
  return { grant, issuedAt: body.at };
}

/**
 * Verifies a token against a pinned trust set and returns what it grants.
 * Throws `AttestError` for a broken signature / unknown key; the gate turns that
 * into `invalid-capability` or `foreign-issuer` so callers can tell them apart.
 */
export function openCapability(receipt: unknown, trust: ReceiptTrust): Capability {
  const body = openReceipt(receipt, trust);
  if (body.action !== CAPABILITY_ISSUED) {
    throw new AgentsError(
      'invalid-capability',
      `receipt "${body.action}" is not a capability (expected ${CAPABILITY_ISSUED})`
    );
  }
  const { grant, issuedAt } = grantFromMeta(body);
  return {
    id: (receipt as { readonly id: string }).id,
    issuer: body.actor,
    subject: grant.subject,
    scopes: grant.scopes,
    actions: grant.actions ?? null,
    notBefore: grant.notBefore ?? 0,
    expiresAt: grant.expiresAt,
    issuedAt,
    receipt: receipt as Receipt,
  };
}

/** Denies a token used outside its validity window. */
export function assertCapabilityLive(capability: Capability, at: number): void {
  if (at < capability.notBefore) {
    throw new AgentsError(
      'capability-not-yet-valid',
      `capability ${capability.id} is not valid before ${capability.notBefore}`
    );
  }
  if (at >= capability.expiresAt) {
    throw new AgentsError(
      'expired-capability',
      `capability ${capability.id} expired at ${capability.expiresAt}`
    );
  }
}

/** Scopes the token does not hold. Empty means the action is inside the token. */
export function missingScopes(
  capability: Capability,
  required: readonly string[]
): readonly string[] {
  const granted = new Set(capability.scopes);
  return required.filter((scope) => !granted.has(scope));
}
