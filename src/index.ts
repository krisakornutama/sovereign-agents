export { AgentsError } from './errors.js';
export type { AgentsErrorCode, AgentsErrorOptions } from './errors.js';
export { ActionRegistry } from './policy.js';
export type { ActionContext, ActionHandler, ActionPolicy, RegisteredAction } from './policy.js';
export {
  CAPABILITY_ISSUED,
  CAPABILITY_REVOKED,
  assertCapabilityLive,
  capabilityStream,
  grantMeta,
  missingScopes,
  normaliseGrant,
  openCapability,
} from './capability.js';
export type { Capability, CapabilityGrant } from './capability.js';
export {
  assertActionName,
  assertActorId,
  assertPrincipal,
  digestOf,
  normaliseScopes,
  streamOf,
} from './names.js';
export type { Principal } from './names.js';
export {
  ACTION_COMPLETED,
  ACTION_DENIED,
  ACTION_FAILED,
  ACTION_REQUESTED,
  AgentGate,
} from './gate.js';
export type {
  CapabilityState,
  DenialReason,
  DenialRecord,
  GateOptions,
  HistoryReport,
  RunResult,
} from './gate.js';
