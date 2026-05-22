/**
 * `LinkAclPromptCoordinator` — the abstract interface for resolving
 * "the user has not granted this caller this scope" prompt requests.
 *
 * The real bridge wires this to a native `NSAlert.runModal()` modal on
 * macOS (`NSAlert` on macOS, `GtkDialog` MODAL on Linux). The mock has
 * no UI, so `MockPromptCoordinator` lets the test script the answer the
 * user "would" give for each prompt that fires.
 *
 * The interface is async and holds the request open while the prompt is
 * pending — matching RFC §7.5's "hold open with a configurable timeout"
 * behaviour. Implementations must respect the supplied timeout.
 */

import type {
  LinkGeoPolicy,
  LinkGeoScope,
} from '../spec/index.js';
import type { LinkAclEntry } from './acl.js';
import type { PeerAttestation } from './peerAttestation.js';

/** Outcome of a prompt resolution. */
export type PromptOutcome =
  /** User clicked "Allow Once" — grant for this single request only. */
  | { kind: 'allow_once' }
  /** User clicked "Allow Always" — persist as `policy=always` in geo-acl.json. */
  | { kind: 'allow_always' }
  /** User clicked "Allow For This SSH Session" — write to geo-acl-session.json. */
  | { kind: 'allow_session'; sshSessionId: string }
  /** User clicked "Deny". */
  | { kind: 'deny' }
  /** User clicked "Deny Always" — persist as `policy=deny` in geo-acl.json. */
  | { kind: 'deny_always' }
  /** Prompt timed out before the user answered. */
  | { kind: 'timeout' };

/** Context passed to the prompt coordinator on every prompt. */
export interface PromptRequest {
  attestation: PeerAttestation;
  scope: LinkGeoScope;
  /** Existing ACL entry, if any (the prompt is informed by current state). */
  existingEntry: LinkAclEntry | null;
  /** Hold-open timeout in seconds (RFC §7.5). */
  timeoutSeconds: number;
  /** Reason the prompt fired (informational). */
  reason: 'no_match' | 'policy_prompt';
}

/** The interface implementations satisfy. */
export interface LinkAclPromptCoordinator {
  /** Resolve a prompt. The implementation MAY block (mock: synchronously,
   *  via a scripted answer queue; real bridge: async via the GUI thread)
   *  but MUST eventually resolve, even if only with `{kind: 'timeout'}`. */
  prompt(request: PromptRequest): Promise<PromptOutcome>;
}

/** A scripted prompt coordinator for tests. Each call to `prompt()`
 *  consumes the next outcome from the queue. If the queue is empty, the
 *  default outcome is returned (defaults to `timeout`). */
export class MockPromptCoordinator implements LinkAclPromptCoordinator {
  private readonly queue: PromptOutcome[] = [];
  private defaultOutcome: PromptOutcome = { kind: 'timeout' };
  private readonly seen: PromptRequest[] = [];

  /** Set the outcome returned when the queue is exhausted. Defaults to
   *  `timeout`. */
  setDefault(outcome: PromptOutcome): this {
    this.defaultOutcome = outcome;
    return this;
  }

  /** Push the next answer the user "gives" the prompt. */
  push(outcome: PromptOutcome): this {
    this.queue.push(outcome);
    return this;
  }

  /** Convenience: enqueue an "Allow Always" answer. */
  pushAllowAlways(): this {
    return this.push({ kind: 'allow_always' });
  }

  /** Convenience: enqueue an "Allow Once". */
  pushAllowOnce(): this {
    return this.push({ kind: 'allow_once' });
  }

  /** Convenience: enqueue a Deny. */
  pushDeny(): this {
    return this.push({ kind: 'deny' });
  }

  /** Inspect every prompt the bridge has fired so far. Returns a
   *  defensive copy so tests don't accidentally mutate state. */
  promptsFired(): PromptRequest[] {
    return this.seen.map((p) => ({ ...p }));
  }

  async prompt(request: PromptRequest): Promise<PromptOutcome> {
    this.seen.push(request);
    return this.queue.shift() ?? this.defaultOutcome;
  }
}

/** Map a prompt outcome to a per-scope ACL policy (where applicable).
 *  Used by the geo engine to update `geo-acl.json` after an `allow_always`
 *  or `deny_always` outcome. */
export function outcomeToPolicy(outcome: PromptOutcome): LinkGeoPolicy | null {
  switch (outcome.kind) {
    case 'allow_always':
      return 'always';
    case 'deny_always':
      return 'deny';
    default:
      return null;
  }
}
