/**
 * BrightLink Protocol — executable spec.
 *
 * Source of truth: docs/rfc-brightlink.md.
 *
 * Every constant in this file traces to the RFC. Wire-level values are
 * pinned: changing one here is a wire-breaking change.
 */

import { Buffer } from 'node:buffer';

// ────────────────────────────────────────────────────────────────────────────
// Protocol-level constants
// ────────────────────────────────────────────────────────────────────────────

/** Protocol version surfaced in `VERSION`. RFC §4.2. */
export const LINK_PROTOCOL_VERSION = 1;

/** Bilateral session-key HKDF info string. RFC §4.5.2.
 *  CRITICAL: changing this string breaks all sessions silently — the
 *  bridge and the client compute different keys with no error path. */
export const LINK_SESSION_KEY_HKDF_INFO = 'brightlink-session-key-v1';

/** Length of the derived session key (AES-256-GCM). */
export const LINK_SESSION_KEY_LENGTH = 32;

// ────────────────────────────────────────────────────────────────────────────
// Command names (wire constants)
// ────────────────────────────────────────────────────────────────────────────

/** Command-name strings on the EBP/1 socket. RFC §4.7. */
export const LINK_COMMANDS = {
  REGISTER:     'LINK_REGISTER',     // §4.5
  DELIVER:      'LINK_DELIVER',      // §4.6
  GEO_STATUS:   'LINK_GEO_STATUS',   // §9.1
  GEO_PROXIMITY:'LINK_GEO_PROXIMITY',// §9.2
  GEO_ZONE:     'LINK_GEO_ZONE',     // §9.3
  GEO_GET:      'LINK_GEO_GET',      // §9.4
  GEO_REFRESH:  'LINK_GEO_REFRESH',  // §9.5
  PUSH:         'LINK_PUSH',         // §10
  AUDIT_EMIT:   'LINK_AUDIT_EMIT',   // §11 — reserved
} as const;

export type LinkCommandName = (typeof LINK_COMMANDS)[keyof typeof LINK_COMMANDS];

/** Stable error-message suffix for "this command is reserved but not yet
 *  implemented." Lets BrightLink-aware clients distinguish a future-aware bridge
 *  from a stale EBP/1-only one (which returns "Unknown command"). */
export const LINK_ERROR_NOT_IMPLEMENTED_SUFFIX = ' not implemented in this build';

// ────────────────────────────────────────────────────────────────────────────
// Session lifetime
// ────────────────────────────────────────────────────────────────────────────

/** Maximum granted TTL: 8 hours. RFC §4.1. */
export const LINK_MAX_TTL_SECONDS = 8 * 3600;

/** Future-skew tolerance for `issuedAtBd` validation. RFC §4.5.1. */
export const LINK_REGISTRATION_FUTURE_SKEW_TOLERANCE_SECONDS = 60;

// ────────────────────────────────────────────────────────────────────────────
// Rate limits (RFC §4.4)
// ────────────────────────────────────────────────────────────────────────────

/** Failed `LINK_REGISTER` attempts per minute per connecting PID. */
export const LINK_REGISTER_FAILURES_PER_MINUTE = 10;

/** Failed in-session `LINK_DELIVER` / `LINK_PUSH` per minute per session. */
export const LINK_IN_SESSION_FAILURES_PER_MINUTE = 30;

// ────────────────────────────────────────────────────────────────────────────
// Standard payload-type identifiers (RFC §5)
// ────────────────────────────────────────────────────────────────────────────

export const LINK_PAYLOAD_TYPES = {
  EPHEMERAL_AUTH:     'ephemeral-auth',     // §5.1
  DB_CONNECTION:      'db-connection',      // §5.2
  GEO_CONTEXT:        'geo-context',        // §5.3
  API_TOKEN:          'api-token',          // §5.4
  CLOUD_SESSION:      'cloud-session',      // §5.5
  SSH_CREDENTIAL:     'ssh-credential',     // §5.6
  KUBECONFIG_CONTEXT: 'kubeconfig-context', // §5.7
  TOTP_SEED:          'totp-seed',          // §5.8
  MTLS_CERT:          'mtls-cert',          // §5.9
  PLAINTEXT:          'plaintext',          // §5.10
} as const;

export type LinkPayloadType =
  (typeof LINK_PAYLOAD_TYPES)[keyof typeof LINK_PAYLOAD_TYPES];

// ────────────────────────────────────────────────────────────────────────────
// LINK_REGISTER envelope plaintext (RFC §4.5.1)
// ────────────────────────────────────────────────────────────────────────────

export const LINK_REGISTER_ENVELOPE_FIELDS = {
  V: 'v',
  CLIENT_PUB: 'clientPub',
  CLIENT_SHARE: 'clientShare',
  ISSUED_AT_BD: 'issuedAtBd',
  TTL_SECONDS: 'ttlSeconds',
  AGENT: 'agent',
} as const;

/** Length of `clientNonce` in bytes. */
export const LINK_CLIENT_NONCE_LENGTH = 16;
/** Length of `clientShare` and `bridgeShare` in bytes. */
export const LINK_SHARE_LENGTH = 32;
/** Length of `sessionId` in bytes (16 raw bytes; 32 lowercase hex on the wire). */
export const LINK_SESSION_ID_LENGTH = 16;

// ────────────────────────────────────────────────────────────────────────────
// Bilateral HKDF inputs (RFC §4.5.2)
// ────────────────────────────────────────────────────────────────────────────

/** Build the HKDF inputs for the bilateral session-key derivation:
 *
 *   IKM   = clientShare ‖ bridgeShare
 *   salt  = clientNonce ‖ sessionId
 *   info  = "brightlink-session-key-v1"
 *   L     = 32
 *
 * Returns the IKM, salt, and info bytes. The HKDF-SHA256 invocation is
 * the caller's responsibility (Swift CryptoKit / @noble/hashes / OpenSSL).
 */
export function buildSessionKeyHkdfInputs(args: {
  clientShare: Uint8Array;
  bridgeShare: Uint8Array;
  clientNonce: Uint8Array;
  sessionId: Uint8Array;
}): { ikm: Buffer; salt: Buffer; info: Buffer; outputByteCount: number } {
  if (args.clientShare.length !== LINK_SHARE_LENGTH) {
    throw new Error(`clientShare must be ${LINK_SHARE_LENGTH} bytes`);
  }
  if (args.bridgeShare.length !== LINK_SHARE_LENGTH) {
    throw new Error(`bridgeShare must be ${LINK_SHARE_LENGTH} bytes`);
  }
  if (args.clientNonce.length !== LINK_CLIENT_NONCE_LENGTH) {
    throw new Error(`clientNonce must be ${LINK_CLIENT_NONCE_LENGTH} bytes`);
  }
  if (args.sessionId.length !== LINK_SESSION_ID_LENGTH) {
    throw new Error(`sessionId must be ${LINK_SESSION_ID_LENGTH} bytes`);
  }
  return {
    ikm: Buffer.concat([Buffer.from(args.clientShare), Buffer.from(args.bridgeShare)]),
    salt: Buffer.concat([Buffer.from(args.clientNonce), Buffer.from(args.sessionId)]),
    info: Buffer.from(LINK_SESSION_KEY_HKDF_INFO, 'utf8'),
    outputByteCount: LINK_SESSION_KEY_LENGTH,
  };
}

// ────────────────────────────────────────────────────────────────────────────
// Canonical 238-byte transcript (RFC §4.5.3)
// ────────────────────────────────────────────────────────────────────────────

export const LINK_TRANSCRIPT_HEADER = Buffer.from('BrightLink v1 transcript\0', 'utf8');

/** Total canonical-transcript byte length. RFC §4.5.3. */
export const LINK_TRANSCRIPT_TOTAL_LENGTH =
  LINK_TRANSCRIPT_HEADER.length          // 25
  + 4 + LINK_CLIENT_NONCE_LENGTH         // 20
  + 4 + 65                               // 69 (clientPub, uncompressed secp256k1)
  + 4 + LINK_SHARE_LENGTH                // 36
  + 4 + LINK_SESSION_ID_LENGTH           // 20
  + 4 + LINK_SHARE_LENGTH                // 36
  + 4 + 8                                // 12 (issuedAtBd as u64 BE)
  + 4 + 8                                // 12 (bridgeIssuedAtUnix as u64 BE)
  + 4 + 4;                               // 8  (ttlSeconds as u32 BE)
// = 238 bytes total.

/** Build the canonical 238-byte transcript per RFC §4.5.3.
 *
 *   "BrightLink v1 transcript\0"                             25 bytes
 *   LE32(len(clientNonce))   ‖ clientNonce                   4 + 16
 *   LE32(len(clientPub))     ‖ clientPub                     4 + 65
 *   LE32(len(clientShare))   ‖ clientShare                   4 + 32
 *   LE32(len(sessionId))     ‖ sessionId                     4 + 16
 *   LE32(len(bridgeShare))   ‖ bridgeShare                   4 + 32
 *   LE32(8)                  ‖ u64_be(round(issuedAtBd*86400))   12
 *   LE32(8)                  ‖ u64_be(bridgeIssuedAtUnix)        12
 *   LE32(4)                  ‖ u32_be(ttlSeconds)                 8
 */
export function buildTranscript(args: {
  clientNonce: Uint8Array;       // 16 bytes
  clientPub: Uint8Array;         // 65 bytes uncompressed secp256k1
  clientShare: Uint8Array;       // 32 bytes
  sessionId: Uint8Array;         // 16 bytes
  bridgeShare: Uint8Array;       // 32 bytes
  issuedAtBd: number;            // BrightDate scalar
  bridgeIssuedAtUnix: number;    // Unix seconds
  ttlSeconds: number;            // u32
}): Buffer {
  if (args.clientNonce.length !== LINK_CLIENT_NONCE_LENGTH) {
    throw new Error(`clientNonce must be ${LINK_CLIENT_NONCE_LENGTH} bytes`);
  }
  if (args.clientPub.length !== 65) {
    throw new Error(`clientPub must be 65 bytes (uncompressed secp256k1)`);
  }
  if (args.clientShare.length !== LINK_SHARE_LENGTH) {
    throw new Error(`clientShare must be ${LINK_SHARE_LENGTH} bytes`);
  }
  if (args.sessionId.length !== LINK_SESSION_ID_LENGTH) {
    throw new Error(`sessionId must be ${LINK_SESSION_ID_LENGTH} bytes`);
  }
  if (args.bridgeShare.length !== LINK_SHARE_LENGTH) {
    throw new Error(`bridgeShare must be ${LINK_SHARE_LENGTH} bytes`);
  }
  if (!Number.isFinite(args.issuedAtBd)) {
    throw new Error(`issuedAtBd must be finite`);
  }
  if (!Number.isInteger(args.bridgeIssuedAtUnix) || args.bridgeIssuedAtUnix < 0) {
    throw new Error(`bridgeIssuedAtUnix must be a non-negative integer`);
  }
  if (!Number.isInteger(args.ttlSeconds) || args.ttlSeconds < 0
      || args.ttlSeconds > 0xffff_ffff) {
    throw new Error(`ttlSeconds must be a u32`);
  }

  const issuedAtUnixRounded = Math.round(args.issuedAtBd * 86400);

  const lenPrefix = (n: number): Buffer => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n, 0);
    return b;
  };
  const u64Be = (n: number): Buffer => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(BigInt(n), 0);
    return b;
  };
  const u32Be = (n: number): Buffer => {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(n, 0);
    return b;
  };

  return Buffer.concat([
    LINK_TRANSCRIPT_HEADER,
    lenPrefix(args.clientNonce.length),
    Buffer.from(args.clientNonce),
    lenPrefix(args.clientPub.length),
    Buffer.from(args.clientPub),
    lenPrefix(args.clientShare.length),
    Buffer.from(args.clientShare),
    lenPrefix(args.sessionId.length),
    Buffer.from(args.sessionId),
    lenPrefix(args.bridgeShare.length),
    Buffer.from(args.bridgeShare),
    lenPrefix(8),
    u64Be(issuedAtUnixRounded),
    lenPrefix(8),
    u64Be(args.bridgeIssuedAtUnix),
    lenPrefix(4),
    u32Be(args.ttlSeconds),
  ]);
}

// ────────────────────────────────────────────────────────────────────────────
// LINK_DELIVER wire format (RFC §4.9)
// ────────────────────────────────────────────────────────────────────────────

/** Direction tag values. RFC §4.6.1, §4.6.2. */
export const LINK_DIR_TAG = {
  /** Shell → Agent (tool delivers credential to bridge). */
  SHELL_TO_AGENT: 0x01,
  /** Agent → Shell (bridge pushes geo events to subscribed shell). */
  AGENT_TO_SHELL: 0x02,
} as const;

export type LinkDirTag = (typeof LINK_DIR_TAG)[keyof typeof LINK_DIR_TAG];

/** Replay-protection window. Receivers accept counters strictly greater
 *  than `lastAccepted`, up to `lastAccepted + LINK_COUNTER_REPLAY_WINDOW`.
 *  RFC §4.6.4. */
export const LINK_COUNTER_REPLAY_WINDOW = 1000;

/** AES-GCM nonce length on the wire. RFC §4.9.1. */
export const LINK_GCM_IV_LENGTH = 12;
/** AES-GCM auth-tag length. */
export const LINK_GCM_TAG_LENGTH = 16;

/** Build the AES-256-GCM AAD for a `LINK_DELIVER` packet, RFC §4.6.3:
 *
 *   AAD = LE32(1) ‖ dir_tag(1)
 *      ‖ LE32(len(counter_bytes)) ‖ counter_bytes(8)
 *      ‖ LE32(len(type_bytes))    ‖ type_bytes
 *      ‖ LE32(len(context_bytes)) ‖ context_bytes
 *
 * The leading `LE32(1)` is the length prefix of the single-byte
 * `dir_tag` field. Don't drop it — its presence keeps the AAD scheme
 * uniformly length-prefixed.
 */
export function buildDeliverAad(args: {
  dirTag: LinkDirTag;
  counter: bigint;
  type: string;
  contextBytes: Uint8Array;
}): Buffer {
  if (args.dirTag !== LINK_DIR_TAG.SHELL_TO_AGENT
      && args.dirTag !== LINK_DIR_TAG.AGENT_TO_SHELL) {
    throw new Error(
      `dirTag must be 0x01 or 0x02, got 0x${(args.dirTag as number).toString(16)}`,
    );
  }
  if (args.counter < 0n || args.counter > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`counter out of u64 range: ${args.counter}`);
  }

  const counterBytes = Buffer.alloc(8);
  counterBytes.writeBigUInt64BE(args.counter, 0);

  const typeBytes = Buffer.from(args.type, 'utf8');
  const ctxBytes = Buffer.from(args.contextBytes);

  const lenLE32 = (n: number): Buffer => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n, 0);
    return b;
  };

  return Buffer.concat([
    lenLE32(1),
    Buffer.from([args.dirTag]),
    lenLE32(counterBytes.length),
    counterBytes,
    lenLE32(typeBytes.length),
    typeBytes,
    lenLE32(ctxBytes.length),
    ctxBytes,
  ]);
}

// ════════════════════════════════════════════════════════════════════════════
//
// Geo surface (RFC §6 Cross-Platform Pluggables, §7 Scope/ACL/Prompts,
//              §8 Zone Algebra, §9 LINK_GEO_*, §10 LINK_PUSH).
//
// Everything below is the geo + push extension to BrightLink. Wire-level
// constants (HKDF info, scope strings, error messages) are pinned: changing
// them is a wire-breaking change.
//
// ════════════════════════════════════════════════════════════════════════════

// ────────────────────────────────────────────────────────────────────────────
// §7.1 — Scope ladder
// ────────────────────────────────────────────────────────────────────────────

/** Scope strings on the wire. RFC §7.1. CRITICAL: changing these is a
 *  wire-breaking change because they're persisted in `geo-acl.json`. */
export const LINK_GEO_SCOPES = {
  STATUS:     'geo:status',     // §9.1 — alive/fix-age boolean only
  PROXIMITY:  'geo:proximity',  // §9.2 — yes/no for a named zone
  ZONE:       'geo:zone',       // §9.3 — current zone identifier + dwell
  PRECISE:    'geo:precise',    // §9.4 — full position
  TRAJECTORY: 'geo:trajectory', // future — position + velocity
} as const;

export type LinkGeoScope =
  (typeof LINK_GEO_SCOPES)[keyof typeof LINK_GEO_SCOPES];

/** Scope rank — strictly increasing. A grant for a higher rung implies
 *  grants for lower rungs (§7.1). */
export const LINK_GEO_SCOPE_RANK: Record<LinkGeoScope, number> = {
  'geo:status':     0,
  'geo:proximity':  1,
  'geo:zone':       2,
  'geo:precise':    3,
  'geo:trajectory': 4,
};

/** Highest scope an unsigned binary may ever hold. RFC §7.1. */
export const LINK_GEO_UNSIGNED_MAX_SCOPE: LinkGeoScope =
  LINK_GEO_SCOPES.PROXIMITY;

/** Per-scope ACL policy values stored in `geo-acl.json` entries. RFC §7.2. */
export const LINK_GEO_POLICIES = {
  ALWAYS: 'always',
  PROMPT: 'prompt',
  DENY:   'deny',
} as const;

export type LinkGeoPolicy =
  (typeof LINK_GEO_POLICIES)[keyof typeof LINK_GEO_POLICIES];

// ────────────────────────────────────────────────────────────────────────────
// §6.2 — Peer attestation classes
// ────────────────────────────────────────────────────────────────────────────

/** Attestation-class strings stored in `geo-acl.json` entries. The bridge
 *  matches `(class, issuer_id, subject_id)` plus `executable_hash` for the
 *  Unsigned class. RFC §6.2. */
export const LINK_ATTESTATION_CLASSES = {
  DEVELOPER_ID:    'DeveloperId',     // macOS: Apple Developer ID + Team ID
  MAC_APP_STORE:   'MacAppStore',     // macOS: Mac App Store
  BSH_BUILTIN:     'BshBuiltin',      // any: signed by the bsh release key
  DPKG_SIGNED:     'DpkgSigned',      // Linux: Debian/Ubuntu .deb signed
  RPM_SIGNED:      'RpmSigned',       // Linux: Red Hat/Fedora .rpm signed
  FLATPAK_SIGNED:  'FlatpakSigned',   // Linux: Flatpak signed
  UNSIGNED:        'Unsigned',        // any: TOFU pin by (path, hash) only
} as const;

export type LinkAttestationClass =
  (typeof LINK_ATTESTATION_CLASSES)[keyof typeof LINK_ATTESTATION_CLASSES];

// ────────────────────────────────────────────────────────────────────────────
// §6.1 — Bridge identity kinds
// ────────────────────────────────────────────────────────────────────────────

/** Kind of `BridgeIdentity` impl in use. The bridge logs this at startup
 *  and writes it to `~/.brightchain/brightnexus/bridge-identity.kind`.
 *  Clients can refuse to register against software-only bridges. RFC §6.1. */
export const LINK_BRIDGE_IDENTITY_KINDS = {
  SEP:  'SepBridgeIdentity',   // macOS Apple Silicon — Secure Enclave
  TPM2: 'Tpm2BridgeIdentity',  // Linux with TPM2
  FILE: 'FileBridgeIdentity',  // any POSIX (software fallback)
} as const;

export type LinkBridgeIdentityKind =
  (typeof LINK_BRIDGE_IDENTITY_KINDS)[keyof typeof LINK_BRIDGE_IDENTITY_KINDS];

// ────────────────────────────────────────────────────────────────────────────
// §8 — Zone shape algebra
// ────────────────────────────────────────────────────────────────────────────

export const LINK_ZONE_SHAPE_TYPES = {
  CIRCLE_2D:   'circle_2d',   // (center, radius_m)
  CYLINDER_3D: 'cylinder_3d', // (center, radius_m, alt_min, alt_max)
  POLYGON_2D:  'polygon_2d',  // (points_wgs84[])
  BBOX_2D:     'bbox_2d',     // (lat_min/max, lon_min/max)
} as const;

export type LinkZoneShapeType =
  (typeof LINK_ZONE_SHAPE_TYPES)[keyof typeof LINK_ZONE_SHAPE_TYPES];

/** Default zone priorities (§8). Most-specific shape wins; user can override
 *  per-zone in `geo-zones.json`. */
export const LINK_ZONE_DEFAULT_PRIORITY: Record<LinkZoneShapeType, number> = {
  circle_2d:   100,
  cylinder_3d: 200,
  polygon_2d:   50,
  bbox_2d:      10,
};

// ────────────────────────────────────────────────────────────────────────────
// §6.3 — Coordinate conversion (WGS84 ↔ ECEF ↔ BrightSpace)
//
// All conversions are exact under IEEE 754 double precision at terrestrial
// scale. ECEF is in metres (ITRF2020 / WGS84 — they share an origin to
// sub-millimetre at the surface). BrightSpace is ECEF / c per the
// BrightSpace standard.
// ────────────────────────────────────────────────────────────────────────────

/** Speed of light in metres per second. Exact since the 1983 SI redefinition
 *  of the metre, and directly the conversion factor between ECEF metres and
 *  BrightSpace BrightMeters per the BrightSpace standard. */
export const SPEED_OF_LIGHT_MPS = 299_792_458;

/** WGS84 ellipsoid semi-major axis in metres. Exact by definition. */
export const WGS84_A = 6_378_137.0;
/** WGS84 ellipsoid flattening. */
export const WGS84_F = 1 / 298.257_223_563;
/** First eccentricity squared, derived: e² = 2f − f². */
export const WGS84_E2 = 2 * WGS84_F - WGS84_F * WGS84_F;
/** Semi-minor axis derived from a and f. */
export const WGS84_B = WGS84_A * (1 - WGS84_F);

export interface Wgs84Point {
  lat: number;        // degrees
  lon: number;        // degrees
  alt_m?: number;     // metres above WGS84 ellipsoid; default 0
}

export interface EcefPoint {
  x_m: number;
  y_m: number;
  z_m: number;
}

export interface BrightSpacePoint {
  x_bm: number;
  y_bm: number;
  z_bm: number;
  /** BrightDate at which the position was sampled (RFC §9.4 + BrightSpace
   *  §6 worked example: long-lived spatial claims SHOULD record sampling
   *  epoch so consumers can re-project through plate-motion velocity). */
  epoch_bd: number;
}

const DEG2RAD = Math.PI / 180;
const RAD2DEG = 180 / Math.PI;

/** WGS84 lat/lon/alt → ECEF metres. Exact closed-form. */
export function wgs84ToEcef(p: Wgs84Point): EcefPoint {
  const phi = p.lat * DEG2RAD;
  const lam = p.lon * DEG2RAD;
  const h = p.alt_m ?? 0;

  const sinPhi = Math.sin(phi);
  const cosPhi = Math.cos(phi);
  const sinLam = Math.sin(lam);
  const cosLam = Math.cos(lam);

  // Radius of curvature in the prime vertical.
  const N = WGS84_A / Math.sqrt(1 - WGS84_E2 * sinPhi * sinPhi);

  return {
    x_m: (N + h) * cosPhi * cosLam,
    y_m: (N + h) * cosPhi * sinLam,
    z_m: (N * (1 - WGS84_E2) + h) * sinPhi,
  };
}

/** ECEF metres → WGS84 lat/lon/alt. Heikkinen 1982 closed-form, no iteration.
 *  Accurate to better than 0.1 mm at the surface; degrades only at the
 *  geocentre (0,0,0) where the answer is undefined anyway. */
export function ecefToWgs84(p: EcefPoint): Wgs84Point {
  const { x_m: x, y_m: y, z_m: z } = p;
  const a = WGS84_A;
  const b = WGS84_B;
  const e2 = WGS84_E2;
  // Second eccentricity squared.
  const ep2 = (a * a - b * b) / (b * b);

  const r = Math.sqrt(x * x + y * y);
  const F = 54 * b * b * z * z;
  const G = r * r + (1 - e2) * z * z - e2 * (a * a - b * b);
  const c = (e2 * e2 * F * r * r) / (G * G * G);
  const s = Math.cbrt(1 + c + Math.sqrt(c * c + 2 * c));
  const P = F / (3 * (s + 1 / s + 1) ** 2 * G * G);
  const Q = Math.sqrt(1 + 2 * e2 * e2 * P);
  const r0 =
    -(P * e2 * r) / (1 + Q) +
    Math.sqrt(
      0.5 * a * a * (1 + 1 / Q) -
        (P * (1 - e2) * z * z) / (Q * (1 + Q)) -
        0.5 * P * r * r,
    );
  const U = Math.sqrt((r - e2 * r0) ** 2 + z * z);
  const V = Math.sqrt((r - e2 * r0) ** 2 + (1 - e2) * z * z);
  const z0 = (b * b * z) / (a * V);

  const alt_m = U * (1 - (b * b) / (a * V));
  const lat = Math.atan2(z + ep2 * z0, r) * RAD2DEG;
  const lon = Math.atan2(y, x) * RAD2DEG;

  return { lat, lon, alt_m };
}

/** ECEF metres → BrightSpace BrightMeters (divide by c). Exact. */
export function ecefToBrightSpace(p: EcefPoint, epoch_bd: number): BrightSpacePoint {
  return {
    x_bm: p.x_m / SPEED_OF_LIGHT_MPS,
    y_bm: p.y_m / SPEED_OF_LIGHT_MPS,
    z_bm: p.z_m / SPEED_OF_LIGHT_MPS,
    epoch_bd,
  };
}

/** BrightSpace BrightMeters → ECEF metres (multiply by c). Exact. */
export function brightSpaceToEcef(p: BrightSpacePoint): EcefPoint {
  return {
    x_m: p.x_bm * SPEED_OF_LIGHT_MPS,
    y_m: p.y_bm * SPEED_OF_LIGHT_MPS,
    z_m: p.z_bm * SPEED_OF_LIGHT_MPS,
  };
}

/** Euclidean ECEF chord distance in metres between two points. The exact
 *  metric for `circle_2d` and `cylinder_3d` zone membership in BrightSpace.
 *  At terrestrial scales the chord-to-surface-distance error is below
 *  1 cm for radii under 200 m, well within zone tolerance. */
export function ecefChordDistance(a: EcefPoint, b: EcefPoint): number {
  const dx = a.x_m - b.x_m;
  const dy = a.y_m - b.y_m;
  const dz = a.z_m - b.z_m;
  return Math.sqrt(dx * dx + dy * dy + dz * dz);
}

// ────────────────────────────────────────────────────────────────────────────
// §10 — LINK_PUSH event types and AAD construction
// ────────────────────────────────────────────────────────────────────────────

/** Event-name strings carried in `LINK_PUSH` frames. RFC §10.1. */
export const LINK_PUSH_EVENTS = {
  /** Zone change observed by the bridge. Body: {from, to, at_bd}. §10. */
  ZONE_TRANSITION:    'zone-transition',
  /** User granted/revoked a geo scope for THIS caller. Body: {scope, policy, by}. */
  GEO_GRANT_CHANGED:  'geo-grant-changed',
} as const;

export type LinkPushEvent =
  (typeof LINK_PUSH_EVENTS)[keyof typeof LINK_PUSH_EVENTS];

/** Build the AES-256-GCM AAD for a `LINK_PUSH` frame. RFC §10.2.
 *
 *   AAD = LE32(1) ‖ 0x02            (dir_tag = AGENT_TO_SHELL)
 *      ‖ LE32(8) ‖ u64_be(counter)
 *      ‖ LE32(len(event_name)) ‖ event_name_utf8
 *      ‖ LE32(0) ‖ ""              (empty context for push events)
 *
 * The empty-context length-prefix of `LE32(0)` is required for symmetry
 * with the LINK_DELIVER AAD scheme — it MUST be present even though it
 * carries no body bytes. */
export function buildPushAad(args: {
  counter: bigint;
  event: string;
}): Buffer {
  if (args.counter < 0n || args.counter > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`counter out of u64 range: ${args.counter}`);
  }

  const counterBytes = Buffer.alloc(8);
  counterBytes.writeBigUInt64BE(args.counter, 0);

  const eventBytes = Buffer.from(args.event, 'utf8');

  const lenLE32 = (n: number): Buffer => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n, 0);
    return b;
  };

  return Buffer.concat([
    lenLE32(1),
    Buffer.from([LINK_DIR_TAG.AGENT_TO_SHELL]),
    lenLE32(counterBytes.length),
    counterBytes,
    lenLE32(eventBytes.length),
    eventBytes,
    lenLE32(0),
    // empty context bytes follow — zero of them
  ]);
}

// ────────────────────────────────────────────────────────────────────────────
// §9.7 — Stable error message strings
// ────────────────────────────────────────────────────────────────────────────

/** Geo command error strings clients SHOULD match on. RFC §9.7. */
export const LINK_GEO_ERRORS = {
  SESSION_NOT_REGISTERED:    'geo: session not registered',
  SCOPE_DENIED_BY_POLICY:    'geo: scope denied by policy',
  SCOPE_UNAVAILABLE_UNSIGNED:'geo: scope unavailable for unsigned binary',
  PROMPT_TIMED_OUT:          'geo: user prompt timed out',
  USER_DENIED:               'geo: user denied',
  PROMPT_UNAVAILABLE:        'geo: prompt unavailable',
  THROTTLED:                 'geo: throttled',
  ENGINE_UNAVAILABLE:        'geo: engine unavailable',
  ZONE_NOT_FOUND:            'geo: zone not found',
  FORMAT_INVALID:            'geo: format invalid',
  REFRESH_TIMED_OUT:         'geo: refresh timed out',
} as const;

/** Push command error strings. RFC §10.5. */
export const LINK_PUSH_ERRORS = {
  SESSION_NOT_REGISTERED: 'push: session not registered',
  UNKNOWN_EVENT_TYPES:    'push: unknown event types',
  SUBSCRIBE_LIMIT:        'push: subscribe limit',
} as const;

