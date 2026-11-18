import { MemoryBlobStore, Vault, randomBytes } from 'sovereign-vault';
import type { AttestVault } from 'sovereign-attest';
import { AgentGate, type DenialRecord } from '../src/index.js';

export interface Faults {
  /** Return true to make the next write to that vault path fail. */
  failPut: ((key: string) => boolean) | null;
}

export interface Fixture {
  vault: Vault;
  gate: AgentGate;
  faults: Faults;
  clock: () => number;
}

/** Deterministic, strictly increasing clock so receipt ids never collide by accident. */
export function tickingClock(start = 1_700_000_000_000): () => number {
  let value = start;
  return () => {
    value += 1;
    return value;
  };
}

export async function makeGate(
  options: { readonly onDenied?: (record: DenialRecord) => void } = {}
): Promise<Fixture> {
  const clock = tickingClock();
  const vault = await Vault.open({
    store: new MemoryBlobStore(),
    masterKey: randomBytes(32),
    clock,
  });
  const faults: Faults = { failPut: null };
  const proxy: AttestVault = {
    get: (key) => vault.get(key),
    put: (key, value) => {
      if (faults.failPut?.(key) === true) {
        return Promise.reject(new Error('simulated store failure'));
      }
      return vault.put(key, value);
    },
    root: () => vault.root(),
    anchorNow: (anchor, at) => vault.anchorNow(anchor as never, at),
    verifyAnchor: (anchor, expectedRoot) => vault.verifyAnchor(anchor as never, expectedRoot),
    pruneOrphans: (options) => vault.pruneOrphans(options),
  };
  const gate = await AgentGate.open({ vault: proxy, keyId: 'agent-gate', now: clock, ...options });
  return { vault, gate, faults, clock };
}
