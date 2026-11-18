/**
 * Errors thrown by the gate. Every code is part of the public contract because
 * callers branch on it (and because a denial must be distinguishable from a bug).
 */
export type AgentsErrorCode =
  | 'invalid-principal'
  | 'invalid-action'
  | 'unknown-action'
  | 'missing-scope'
  | 'invalid-capability'
  | 'foreign-issuer'
  | 'capability-not-yet-valid'
  | 'expired-capability'
  | 'revoked-capability'
  | 'duplicate-action'
  | 'invalid-args'
  | 'receipt-required'
  | 'handler-failed';

export interface AgentsErrorOptions {
  readonly cause?: unknown;
  /** The receipt that proved what happened, when one was written. */
  readonly receiptId?: string;
}

export class AgentsError extends Error {
  readonly code: AgentsErrorCode;
  readonly receiptId?: string;

  constructor(code: AgentsErrorCode, message: string, options: AgentsErrorOptions = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'AgentsError';
    this.code = code;
    if (options.receiptId !== undefined) this.receiptId = options.receiptId;
  }
}
