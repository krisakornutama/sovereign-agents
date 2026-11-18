import { sha256Hex, canonicalJson } from 'sovereign-attest';
import type { AgentsErrorCode } from './errors.js';
import { AgentsError } from './errors.js';

/**
 * Names and scopes are the only free-form text the gate accepts. Both are
 * logged and printed, so they are validated instead of trusted: no whitespace
 * tricks, no control characters, no unbounded strings.
 */
const ACTION_NAME = /^[a-z][a-z0-9._:-]{0,127}$/;
const SCOPE_NAME = /^[a-z][a-z0-9._:-]{0,63}$/;
const MAX_SCOPES = 32;

export function assertActionName(value: unknown): string {
  if (typeof value !== 'string') {
    throw new AgentsError('invalid-action', 'action name must be a string');
  }
  const name = value.trim();
  if (!ACTION_NAME.test(name)) {
    throw new AgentsError('invalid-action', 'action name must match ^[a-z][a-z0-9._:-]{0,127}$');
  }
  return name;
}

export function assertActorId(value: unknown): string {
  if (typeof value !== 'string') {
    throw new AgentsError('invalid-principal', 'principal id must be a string');
  }
  const id = value.trim();
  if (id.length === 0 || id.length > 200) {
    throw new AgentsError('invalid-principal', 'principal id must be 1-200 characters');
  }
  if ([...id].some((ch) => ch.charCodeAt(0) < 0x20 || ch.charCodeAt(0) === 0x7f)) {
    throw new AgentsError('invalid-principal', 'principal id must not contain control characters');
  }
  return id;
}

export function normaliseScopes(
  value: unknown,
  code: AgentsErrorCode,
  field: string
): readonly string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new AgentsError(code, `${field} must be an array of scope strings`);
  }
  const scopes: string[] = [];
  for (const entry of value) {
    if (typeof entry !== 'string') {
      throw new AgentsError(code, `${field} must contain only strings`);
    }
    const scope = entry.trim();
    if (!SCOPE_NAME.test(scope)) {
      throw new AgentsError(code, `${field} entries must match ^[a-z][a-z0-9._:-]{0,63}$`);
    }
    if (!scopes.includes(scope)) scopes.push(scope);
  }
  if (scopes.length > MAX_SCOPES) {
    throw new AgentsError(code, `${field} must contain at most ${MAX_SCOPES} scopes`);
  }
  return scopes;
}

export interface Principal {
  readonly id: string;
  readonly scopes: readonly string[];
}

/** Validates the caller-supplied identity before any receipt is written. */
export function assertPrincipal(value: unknown): Principal {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new AgentsError('invalid-principal', 'principal must be an object with id and scopes');
  }
  const raw = value as { readonly id?: unknown; readonly scopes?: unknown };
  return {
    id: assertActorId(raw.id),
    scopes: normaliseScopes(raw.scopes, 'invalid-principal', 'principal.scopes'),
  };
}

/** Digest of a stored action stream: one hash chain per actor. */
export function streamOf(actor: string): string {
  return sha256Hex(canonicalJson({ kind: 'sovereign-agents/actor', v: 1, id: actor }));
}

/** Digest of arbitrary JSON. Used for requests and results; never stores the value. */
export function digestOf(value: unknown): string {
  return sha256Hex(canonicalJson(value ?? null));
}
