/** Type definitions for `mock-brightnexus`. */

import type { Buffer } from 'node:buffer';

import type { GeoSource } from './geoSource.js';
import type { LinkAclPromptCoordinator } from './promptCoordinator.js';
import type { PeerAttestationProvider } from './peerAttestation.js';
import type { ZoneDefinition } from './zoneEngine.js';

/** A registered BrightLink session. Stored per-connection. */
export interface LinkSession {
  /** 16-byte session identifier. */
  sessionId: Buffer;
  /** 32-byte derived session key (AES-256-GCM key). */
  kSession: Buffer;
  /** Bridge-issued seconds-since-epoch when the session was created. */
  bridgeIssuedAtUnix: number;
  /** Effective expiry time (Unix seconds). */
  expiresAtUnix: number;
  /** Granted TTL (≤ requested, ≤ MAX_TTL). */
  ttlSeconds: number;
  /** Outbound (Agent → Shell) counter — bridge increments before each push. */
  outboundCounter: bigint;
  /** Highest accepted inbound (Shell → Agent) counter for replay defense. */
  lastInboundCounter: bigint;
  /** Free-form agent identification from the §4.5.1 envelope plaintext. */
  agentInfo: { name: string; version: string; platform: string };
}

/** An audit event the mock has recorded. Mirrors the in-memory log of the
 *  real bridge per RFC §11.3 but available for direct assertion in tests. */
export interface AuditEvent {
  /** When the event was recorded (Unix milliseconds). */
  timestampMs: number;
  /** Event kind from RFC §11.3 (`session_init`, `session_teardown`,
   *  `advisory_refusal`, `advisory_override`, etc.) and the §7.7 geo
   *  audit kinds (`geo:allowed_by_acl`, `geo:denied_by_prompt`, etc.). */
  kind: string;
  /** Optional session id (hex) for session-scoped events. */
  sessionIdHex?: string;
  /** Free-form structured payload. */
  payload: Record<string, unknown>;
}

/** A push event queued for a subscriber. The new §10 surface uses this for
 *  zone-transition and geo-grant-changed events; the legacy v3-shaped
 *  push surface is being phased out. */
export interface PushEvent {
  /** JSON-encoded push event frame. */
  sequence: string;
}

/** Constructor options. All optional — sane defaults are provided. */
export interface MockBrightNexusOptions {
  /** Override the secp256k1 private key used as the persistent ECIES key.
   *  Useful for known-answer testing. */
  secp256k1Priv?: Buffer;
  /** Override the P-256 private key used as the SEP / BridgeIdentity stand-in.
   *  Useful for known-answer testing. */
  p256Priv?: Buffer;
  /** Pluggable RNG. Defaults to crypto.randomBytes. Tests pass a fixed
   *  byte source so generated nonces, sessionIds, etc. are deterministic. */
  rng?: (n: number) => Buffer;
  /** Override the bridge-side clock. Returns Unix seconds. */
  nowUnix?: () => number;

  // ── Geo Wave 2 additions ─────────────────────────────────────────────

  /** Pluggable peer-attestation provider (RFC §6.2). The mock cannot
   *  introspect real processes, so tests inject the attestation they want
   *  the bridge to see. Defaults to a provider that returns the unsigned
   *  local-script attestation. */
  peerAttestation?: PeerAttestationProvider;

  /** Pluggable geo source (RFC §6.3). Defaults to a `FixedGeoSource`
   *  with no fix pinned (so `geo:status` reports `alive: false`). */
  geoSource?: GeoSource;

  /** Pluggable prompt coordinator (RFC §7.5). Defaults to a coordinator
   *  that times out every prompt — tests that exercise the prompt flow
   *  inject a `MockPromptCoordinator`. */
  promptCoordinator?: LinkAclPromptCoordinator;

  /** Initial zone definitions (RFC §8). The user normally adds these
   *  through the GUI; tests pre-populate them at construction time. */
  initialZones?: ZoneDefinition[];

  /** Hold-open prompt timeout in seconds (RFC §7.5). Default 30s. */
  promptTimeoutSeconds?: number;
}

