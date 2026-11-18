import { AgentsError } from './errors.js';
import { assertActionName, normaliseScopes } from './names.js';

export interface ActionContext {
  readonly actor: string;
  readonly action: string;
  /** Id of the receipt that was sealed *before* this handler was called. */
  readonly receiptId: string;
  readonly mutating: boolean;
}

export type ActionHandler<TArgs = unknown> = (
  args: TArgs,
  context: ActionContext
) => unknown | Promise<unknown>;

export interface ActionPolicy {
  /** Every scope a principal must hold before the handler is allowed to run. */
  readonly scopes?: readonly string[];
  /** Marks actions that change data (recorded in the receipt; read-only is the default). */
  readonly mutating?: boolean;
  readonly description?: string;
}

export interface RegisteredAction {
  readonly name: string;
  readonly policy: ActionPolicy;
  readonly handler: ActionHandler;
}

/**
 * Deny-by-default registry. Only actions defined here can ever run, and an
 * action cannot be silently redefined by a later caller.
 */
export class ActionRegistry {
  private readonly actions = new Map<string, RegisteredAction>();

  define(name: unknown, handler: unknown, policy: unknown = {}): RegisteredAction {
    const action = assertActionName(name);
    if (typeof handler !== 'function') {
      throw new AgentsError('invalid-action', `handler for "${action}" must be a function`);
    }
    if (this.actions.has(action)) {
      throw new AgentsError('duplicate-action', `action "${action}" is already registered`);
    }
    if (typeof policy !== 'object' || policy === null || Array.isArray(policy)) {
      throw new AgentsError('invalid-action', `policy for "${action}" must be an object`);
    }
    const input = policy as ActionPolicy;
    const scopes = normaliseScopes(input.scopes, 'invalid-action', `scopes for "${action}"`);
    if (input.mutating !== undefined && typeof input.mutating !== 'boolean') {
      throw new AgentsError('invalid-action', `mutating for "${action}" must be a boolean`);
    }
    if (
      input.description !== undefined &&
      (typeof input.description !== 'string' ||
        input.description.trim().length === 0 ||
        input.description.length > 200)
    ) {
      throw new AgentsError(
        'invalid-action',
        `description for "${action}" must be 1-200 characters`
      );
    }

    const registered: RegisteredAction = {
      name: action,
      handler: handler as ActionHandler,
      policy: {
        scopes,
        ...(input.mutating === undefined ? {} : { mutating: input.mutating }),
        ...(input.description === undefined ? {} : { description: input.description.trim() }),
      },
    };
    this.actions.set(action, registered);
    return registered;
  }

  get(name: string): RegisteredAction | undefined {
    return this.actions.get(name);
  }

  names(): readonly string[] {
    return [...this.actions.keys()].sort();
  }
}
