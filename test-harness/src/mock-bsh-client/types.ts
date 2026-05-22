/**
 * Type definitions for `mock-bsh-client`.
 */

import type { Buffer } from 'node:buffer';

/** Result of a successful LINK_REGISTER. The mock holds this internally;
 *  tests can introspect via `client.session`. */
export interface LinkClientSession {
  /** 16-byte session identifier returned by the bridge. */
  sessionId: Buffer;
  /** 32-byte derived AES-256-GCM key. */
  kSession: Buffer;
  /** Bridge's clock when the session was minted (Unix seconds). */
  bridgeIssuedAtUnix: number;
  /** Granted TTL (≤ requested, ≤ 8h). */
  ttlSeconds: number;
  /** Effective expiry (Unix seconds). */
  expiresAtUnix: number;
  /** Bridge's pinned SEP public key (65-byte uncompressed). */
  sepPublicKey: Buffer;
  /** Outbound (Shell → Agent) counter — incremented per emit. */
  outboundCounter: bigint;
  /** Highest accepted inbound (Agent → Shell) counter. */
  lastInboundCounter: bigint;
}

/** Construction options for the mock. */
export interface MockBshClientOptions {
  /** Bridge clock skew tolerance for the receiving side. Defaults to allow
   *  the bridge to be within ±60s of the client (matching RFC §4.5.1's
   *  futureSkewTolerance). Tests rarely override this. */
  clockSkewToleranceSeconds?: number;
  /** Pluggable RNG (testing). Defaults to crypto.randomBytes. */
  rng?: (n: number) => Buffer;
  /** Pluggable client clock (Unix seconds). Tests pin this for deterministic
   *  `issuedAtBd` values. */
  nowUnix?: () => number;
  /** Optional explicit ephemeral keys for LINK_REGISTER. If omitted, fresh
   *  random keys are generated per registration. Used by known-answer tests. */
  ephemeralPrivKey?: Buffer;
  /** Identification advertised in the §4.5.1 envelope's `agent` field. */
  agentInfo?: { name: string; version: string; platform: string };
}
