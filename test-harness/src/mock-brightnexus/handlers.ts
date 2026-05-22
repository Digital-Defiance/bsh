/**
 * Per-command dispatch for `mock-brightnexus`.
 *
 * Each handler returns a Buffer — the response bytes that the socket server
 * writes back to the client. The shape of each response matches the EBP/1
 * spec exactly. Error responses use the canonical strings from
 * `EBP1_ERRORS` and `LINK_ERROR_NOT_IMPLEMENTED_SUFFIX`.
 *
 * Important: this file does NOT import any wire-level magic from the real
 * BrightNexus or `enclave-bridge-client`. Every byte produced here comes
 * from `src/spec/`. That's the whole point of the mock — it's an independent
 * derivation of the spec.
 */

import { Buffer } from 'node:buffer';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

import {
  // EBP/1
  EBP1_COMMANDS,
  EBP1_ERRORS,
  EBP1_KEY_IDS,
  EBP1_KEY_TYPES,
  EBP1_SERVICE_NAME,
  BRIGHTNEXUS_APP_NAME,
  // BrightLink
  LINK_COMMANDS,
  LINK_ERROR_NOT_IMPLEMENTED_SUFFIX,
  LINK_PROTOCOL_VERSION,
  LINK_CLIENT_NONCE_LENGTH,
  LINK_SHARE_LENGTH,
  LINK_SESSION_ID_LENGTH,
  LINK_SESSION_KEY_LENGTH,
  LINK_MAX_TTL_SECONDS,
  LINK_REGISTRATION_FUTURE_SKEW_TOLERANCE_SECONDS,
  buildSessionKeyHkdfInputs,
  buildTranscript,
  // ECIES
  ECIES_AUTH_TAG_SIZE,
  ECIES_HKDF_INFO,
  ECIES_HKDF_OUTPUT_LENGTH,
  ECIES_IV_SIZE,
  ECIES_PUBLIC_KEY_LENGTH,
  ECIES_VERSION_BYTE,
  ECIES_CIPHER_SUITE_BYTE,
  ECIES_ENCRYPTION_TYPE,
} from '../spec/index.js';

import { EciesDecryptError } from './eciesKey.js';
import type { LinkSession, AuditEvent, MockBrightNexusOptions } from './types.js';
import { createSoftSep } from './softSep.js';
import { createMockEciesKey } from './eciesKey.js';
import { createCipheriv, createDecipheriv } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  LINK_DIR_TAG,
  LINK_GCM_IV_LENGTH,
  LINK_GCM_TAG_LENGTH,
  LINK_COUNTER_REPLAY_WINDOW,
  LINK_GEO_ERRORS,
  buildDeliverAad,
} from '../spec/index.js';

import { SoftwareBridgeIdentity, type BridgeIdentity } from './bridgeIdentity.js';
import { LinkAcl } from './acl.js';
import { LinkZoneEngine } from './zoneEngine.js';
import {
  LinkGeoEngine,
  type CoordinateFormat,
  type GeoAuditEntry,
} from './geoEngine.js';
import { FixedGeoSource, type GeoSource } from './geoSource.js';
import {
  MockPromptCoordinator,
  type LinkAclPromptCoordinator,
} from './promptCoordinator.js';
import {
  MockPeerAttestationProvider,
  type PeerAttestation,
  type PeerAttestationProvider,
} from './peerAttestation.js';

/** Pluggable RNG type. */
type Rng = (n: number) => Buffer;

/** BrightDate epoch (UTC label, Unix ms). Per the BrightDate specification. */
const J2000_UTC_UNIX_MS = 946_727_935_816;

/** Per-process state shared across all connections. The socket-server module
 *  constructs one of these and passes it to each per-connection handler. */
export class BridgeState {
  readonly secp256k1Key: ReturnType<typeof createMockEciesKey>;
  readonly sep: ReturnType<typeof createSoftSep>;
  readonly bridgeIdentity: BridgeIdentity;
  readonly rng: Rng;
  readonly nowUnix: () => number;
  readonly auditLog: AuditEvent[] = [];
  readonly startTime = Date.now();
  readonly options: MockBrightNexusOptions;

  // Geo Wave 2 surfaces.
  readonly peerAttestation: PeerAttestationProvider;
  readonly geoSource: GeoSource;
  readonly promptCoordinator: LinkAclPromptCoordinator;
  readonly zones: LinkZoneEngine;
  readonly acl: LinkAcl;
  readonly geo: LinkGeoEngine;

  constructor(options: MockBrightNexusOptions = {}) {
    this.options = options;
    this.secp256k1Key = createMockEciesKey(options.secp256k1Priv);
    this.sep = createSoftSep(options.p256Priv);
    this.rng = options.rng ?? defaultRng();
    this.nowUnix = options.nowUnix ?? (() => Math.floor(Date.now() / 1000));

    // Bridge identity wraps the same software P-256 key as the SEP — so the
    // §4.5 transcript and the §7 ACL are signed by the same identity in
    // the mock, which mirrors the real bridge's per-user single-identity model.
    this.bridgeIdentity = new SoftwareBridgeIdentity(this.sep.privateKeyRaw());

    this.peerAttestation = options.peerAttestation ?? new MockPeerAttestationProvider();
    this.geoSource = options.geoSource ?? new FixedGeoSource({ nowUnix: this.nowUnix });
    this.promptCoordinator = options.promptCoordinator ?? new MockPromptCoordinator();
    this.zones = new LinkZoneEngine();
    if (options.initialZones) this.zones.setZones(options.initialZones);
    this.acl = new LinkAcl(this.bridgeIdentity);

    this.geo = new LinkGeoEngine({
      source: this.geoSource,
      zones: this.zones,
      acl: this.acl,
      prompt: this.promptCoordinator,
      audit: { recordGeoEvent: (e) => this.recordGeoAudit(e) },
      nowBd: () => this.nowBrightDate(),
      promptTimeoutSeconds: options.promptTimeoutSeconds ?? 30,
    });
  }

  uptimeSeconds(): number {
    return Math.floor((Date.now() - this.startTime) / 1000);
  }

  recordAudit(event: Omit<AuditEvent, 'timestampMs'>): void {
    this.auditLog.push({ ...event, timestampMs: Date.now() });
  }

  /** BrightDate at the bridge's current clock. */
  nowBrightDate(): number {
    return (this.nowUnix() * 1000 - J2000_UTC_UNIX_MS) / 86_400_000;
  }

  /** Convert a `GeoAuditEntry` from the geo engine into the bridge's flat
   *  audit-log shape. The kind is prefixed `geo:` so tests can filter. */
  private recordGeoAudit(entry: GeoAuditEntry): void {
    this.recordAudit({
      kind: `geo:${entry.decision}`,
      payload: {
        brightdate: entry.brightdate,
        command: entry.command,
        scope: entry.scope,
        policyAtDecision: entry.policyAtDecision,
        peer: {
          pid: entry.attestation.pid,
          uid: entry.attestation.uid,
          executablePath: entry.attestation.executablePath,
          attestationClass: entry.attestation.attestationClass,
          issuerId: entry.attestation.issuerId,
          subjectId: entry.attestation.subjectId,
          signatureValid: entry.attestation.signatureValid,
        },
        sshSession: entry.attestation.sshSession,
        responseSummary: entry.responseSummary,
      },
    });
  }
}

function defaultRng(): Rng {
  // Lazily resolve to avoid loading node:crypto.randomBytes at module init.
  const { randomBytes } = require('node:crypto') as typeof import('node:crypto');
  return (n) => Buffer.from(randomBytes(n));
}

/** State held per accepted connection. */
export class ConnectionState {
  /** Set by SET_PEER_PUBLIC_KEY. */
  peerPublicKey?: Buffer;
  /** BrightLink session bound to this connection (at most one). */
  linkSession?: LinkSession;
  /** Whether this connection has an active LINK_PUSH subscription. */
  pushSubscribed = false;
  /** Peer attestation captured at `accept(2)` time. The socket server
   *  pulls this from the `BridgeState.peerAttestation` provider on each
   *  new connection. Used by every `LINK_GEO_*` handler to identify the
   *  caller. */
  attestation: PeerAttestation | null = null;
}

// ────────────────────────────────────────────────────────────────────────────
// Top-level dispatch
// ────────────────────────────────────────────────────────────────────────────

export async function handleMessage(
  data: Buffer,
  bridge: BridgeState,
  conn: ConnectionState,
): Promise<Buffer> {
  let req: Record<string, unknown>;
  try {
    req = JSON.parse(data.toString('utf8'));
  } catch {
    return errorResponse(EBP1_ERRORS.INVALID_REQUEST_FORMAT);
  }
  const cmd = req['cmd'];
  if (typeof cmd !== 'string') {
    return errorResponse(EBP1_ERRORS.INVALID_REQUEST_FORMAT);
  }

  switch (cmd) {
    // EBP/1 core
    case EBP1_COMMANDS.HEARTBEAT:
      return jsonResponse({
        ok: true,
        timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
        service: EBP1_SERVICE_NAME,
      });
    case EBP1_COMMANDS.VERSION:
    case EBP1_COMMANDS.INFO:
      return jsonResponse({
        appVersion: 'mock',
        build: '0',
        platform: 'mock',
        uptimeSeconds: bridge.uptimeSeconds(),
        app: BRIGHTNEXUS_APP_NAME,
        brightlinkProtocolVersion: LINK_PROTOCOL_VERSION,
      });
    case EBP1_COMMANDS.STATUS:
      return jsonResponse({
        ok: true,
        peerPublicKeySet: conn.peerPublicKey !== undefined,
        enclaveKeyAvailable: true,
      });
    case EBP1_COMMANDS.METRICS:
      return jsonResponse({
        uptimeSeconds: bridge.uptimeSeconds(),
        service: EBP1_SERVICE_NAME,
        requestCounters: {},
      });
    case EBP1_COMMANDS.GET_PUBLIC_KEY:
      return jsonResponse({
        publicKey: bridge.secp256k1Key.getPublicKey().toString('base64'),
      });
    case EBP1_COMMANDS.GET_ENCLAVE_PUBLIC_KEY:
      return jsonResponse({
        publicKey: bridge.sep.publicKey().toString('base64'),
      });
    case EBP1_COMMANDS.SET_PEER_PUBLIC_KEY:
      return handleSetPeerPublicKey(req, conn);
    case EBP1_COMMANDS.LIST_KEYS:
      return handleListKeys(bridge);
    case EBP1_COMMANDS.ENCLAVE_SIGN:
      return handleEnclaveSign(req, bridge);
    case EBP1_COMMANDS.ENCLAVE_DECRYPT:
      return handleEnclaveDecrypt(req, bridge);
    case EBP1_COMMANDS.ENCLAVE_GENERATE_KEY:
      return errorResponse(EBP1_ERRORS.ENCLAVE_GENERATE_KEY_NOT_IMPLEMENTED);
    case EBP1_COMMANDS.ENCLAVE_ROTATE_KEY:
      return errorResponse(EBP1_ERRORS.ENCLAVE_ROTATE_KEY_NOT_SUPPORTED);
    case EBP1_COMMANDS.ENABLE_TOTP:
      // Mock doesn't implement TOTP — we return the spec error so a caller
      // testing the EBP/1 surface sees a stable failure path. Real bridge
      // implements this; clients should test against real bridge for TOTP.
      return errorResponse(EBP1_ERRORS.FAILED_TO_ENABLE_TOTP);
    case EBP1_COMMANDS.EXPORT_KEY:
      return handleExportKey(req, bridge);

    // BrightLink v1 — credential delivery
    case LINK_COMMANDS.REGISTER:
      return handleLinkRegister(req, bridge, conn);
    case LINK_COMMANDS.DELIVER:
      return handleLinkDeliver(req, bridge, conn);
    case LINK_COMMANDS.PUSH:
      // LINK_PUSH semantics are handled by the socket-server layer (it must
      // NOT return a single response — it holds the connection open and
      // emits push event frames). The server checks the cmd before
      // delegating here, so we shouldn't reach this branch on the happy path.
      // If we do, return a usage error.
      return errorResponse(`${cmd} requires socket-server-level handling`);

    // BrightLink v1.1 — geo command surface (RFC §9)
    case LINK_COMMANDS.GEO_STATUS:
      return handleLinkGeoStatus(req, bridge, conn);
    case LINK_COMMANDS.GEO_PROXIMITY:
      return handleLinkGeoProximity(req, bridge, conn);
    case LINK_COMMANDS.GEO_ZONE:
      return handleLinkGeoZone(req, bridge, conn);
    case LINK_COMMANDS.GEO_GET:
      return handleLinkGeoGet(req, bridge, conn);
    case LINK_COMMANDS.GEO_REFRESH:
      return handleLinkGeoRefresh(req, bridge, conn);

    // LINK_AUDIT_EMIT — reserved per RFC §11.
    case LINK_COMMANDS.AUDIT_EMIT:
      return errorResponse(`${cmd}${LINK_ERROR_NOT_IMPLEMENTED_SUFFIX}`);

    default:
      return errorResponse(`${EBP1_ERRORS.UNKNOWN_COMMAND_PREFIX}${cmd}`);
  }
}

// ────────────────────────────────────────────────────────────────────────────
// EBP/1 handler bodies
// ────────────────────────────────────────────────────────────────────────────

function handleSetPeerPublicKey(
  req: Record<string, unknown>,
  conn: ConnectionState,
): Buffer {
  const keyStr = req['publicKey'];
  if (typeof keyStr !== 'string') {
    return errorResponse(EBP1_ERRORS.MISSING_OR_INVALID_PUBLIC_KEY);
  }
  const buf = tryBase64(keyStr);
  if (!buf) {
    return errorResponse(EBP1_ERRORS.MISSING_OR_INVALID_PUBLIC_KEY);
  }
  conn.peerPublicKey = buf;
  return jsonResponse({ ok: true });
}

function handleListKeys(bridge: BridgeState): Buffer {
  const eciesPub = bridge.secp256k1Key.getPublicKey();
  const sepPub = bridge.sep.publicKey();
  return jsonResponse({
    keys: [
      {
        id: EBP1_KEY_IDS.ECIES_SECP256K1,
        type: EBP1_KEY_TYPES.SECP256K1,
        publicKeyFingerprint: fingerprint(eciesPub),
        isSecureEnclave: false,
        totpEnabled: false,
        totpProvisioningURI: '',
      },
      {
        id: EBP1_KEY_IDS.SECURE_ENCLAVE_P256,
        type: EBP1_KEY_TYPES.SECURE_ENCLAVE_P256,
        publicKeyFingerprint: fingerprint(sepPub),
        isSecureEnclave: true,
        totpEnabled: false,
        totpProvisioningURI: '',
      },
    ],
  });
}

function handleEnclaveSign(req: Record<string, unknown>, bridge: BridgeState): Buffer {
  const dataStr = req['data'];
  if (typeof dataStr !== 'string') {
    return errorResponse(EBP1_ERRORS.MISSING_OR_INVALID_DATA_TO_SIGN);
  }
  const data = tryBase64(dataStr);
  if (!data) {
    return errorResponse(EBP1_ERRORS.MISSING_OR_INVALID_DATA_TO_SIGN);
  }
  const sig = bridge.sep.sign(data);
  return jsonResponse({ signature: sig.toString('base64') });
}

function handleEnclaveDecrypt(
  req: Record<string, unknown>,
  bridge: BridgeState,
): Buffer {
  const dataStr = req['data'];
  if (typeof dataStr !== 'string') {
    return errorResponse(EBP1_ERRORS.MISSING_OR_INVALID_DATA_TO_DECRYPT);
  }
  const envelope = tryBase64(dataStr);
  if (!envelope) {
    return errorResponse(EBP1_ERRORS.MISSING_OR_INVALID_DATA_TO_DECRYPT);
  }
  try {
    const plaintext = bridge.secp256k1Key.decryptEnvelope(envelope);
    return jsonResponse({ plaintext: plaintext.toString('base64') });
  } catch (e) {
    if (e instanceof EciesDecryptError) {
      return errorResponse(e.ebp1Error);
    }
    return errorResponse(EBP1_ERRORS.DECRYPTION_FAILED);
  }
}

function handleExportKey(req: Record<string, unknown>, bridge: BridgeState): Buffer {
  const keyId = req['keyId'];
  if (typeof keyId !== 'string') {
    return errorResponse(EBP1_ERRORS.MISSING_KEYID);
  }
  // Mock has no TOTP; spec says EXPORT_KEY for a non-TOTP key behaves like
  // GET_PUBLIC_KEY / GET_ENCLAVE_PUBLIC_KEY. RFC §4.14 last paragraph.
  if (keyId === EBP1_KEY_IDS.ECIES_SECP256K1) {
    return jsonResponse({
      publicKey: bridge.secp256k1Key.getPublicKey().toString('base64'),
    });
  }
  if (keyId === EBP1_KEY_IDS.SECURE_ENCLAVE_P256) {
    return jsonResponse({ publicKey: bridge.sep.publicKey().toString('base64') });
  }
  return errorResponse(EBP1_ERRORS.UNKNOWN_KEYID);
}

// ────────────────────────────────────────────────────────────────────────────
// LINK_REGISTER (RFC §4.5)
// ────────────────────────────────────────────────────────────────────────────

function handleLinkRegister(
  req: Record<string, unknown>,
  bridge: BridgeState,
  conn: ConnectionState,
): Buffer {
  if (req['protocolVersion'] !== LINK_PROTOCOL_VERSION) {
    return errorResponse('Unsupported SDI protocol version');
  }

  // Decode clientNonce.
  const clientNonceStr = req['clientNonce'];
  if (typeof clientNonceStr !== 'string') {
    return errorResponse('Missing clientNonce');
  }
  const clientNonce = tryBase64(clientNonceStr);
  if (!clientNonce || clientNonce.length !== LINK_CLIENT_NONCE_LENGTH) {
    return errorResponse('Missing clientNonce');
  }

  // Decode envelope.
  const envelopeStr = req['envelope'];
  if (typeof envelopeStr !== 'string') {
    return errorResponse('Missing envelope');
  }
  const envelope = tryBase64(envelopeStr);
  if (!envelope) {
    return errorResponse('Missing envelope');
  }

  // ECIES-decrypt the envelope to recover the §4.5.1 plaintext.
  let plaintextBytes: Buffer;
  try {
    plaintextBytes = bridge.secp256k1Key.decryptEnvelope(envelope);
  } catch (e) {
    if (e instanceof EciesDecryptError && e.ebp1Error === 'Decryption failed') {
      return errorResponse('Decryption failed');
    }
    return errorResponse('Decryption failed');
  }

  // Parse the §4.5.1 plaintext schema.
  let plaintext: {
    v?: unknown;
    clientPub?: unknown;
    clientShare?: unknown;
    issuedAtBd?: unknown;
    ttlSeconds?: unknown;
    agent?: unknown;
  };
  try {
    plaintext = JSON.parse(plaintextBytes.toString('utf8'));
  } catch {
    return errorResponse('Invalid envelope plaintext');
  }
  if (plaintext.v !== LINK_PROTOCOL_VERSION) {
    return errorResponse('Invalid envelope plaintext');
  }
  if (typeof plaintext.clientPub !== 'string') {
    return errorResponse('Invalid envelope plaintext');
  }
  const clientPub = tryBase64(plaintext.clientPub);
  // §4.5.1 says clientPub is a 65-byte uncompressed secp256k1 public key.
  if (!clientPub || clientPub.length !== 65 || clientPub[0] !== 0x04) {
    return errorResponse('Invalid envelope plaintext');
  }
  if (typeof plaintext.clientShare !== 'string') {
    return errorResponse('Invalid envelope plaintext');
  }
  const clientShare = tryBase64(plaintext.clientShare);
  if (!clientShare || clientShare.length !== LINK_SHARE_LENGTH) {
    return errorResponse('Invalid envelope plaintext');
  }
  if (typeof plaintext.issuedAtBd !== 'number' || !Number.isFinite(plaintext.issuedAtBd)) {
    return errorResponse('Invalid envelope plaintext');
  }
  if (typeof plaintext.ttlSeconds !== 'number' || !Number.isInteger(plaintext.ttlSeconds)) {
    return errorResponse('Invalid envelope plaintext');
  }
  // Agent block — required structurally but we accept any string fields.
  let agentInfo = { name: 'unknown', version: 'unknown', platform: 'unknown' };
  if (
    typeof plaintext.agent === 'object' &&
    plaintext.agent !== null
  ) {
    const a = plaintext.agent as Record<string, unknown>;
    if (typeof a['name'] === 'string') agentInfo.name = a['name'];
    if (typeof a['version'] === 'string') agentInfo.version = a['version'];
    if (typeof a['platform'] === 'string') agentInfo.platform = a['platform'];
  }

  // Clock-skew check per RFC §4.5.1: bridges MUST reject issuedAtBd that
  // resolves to more than 60 seconds in the future of the bridge clock.
  const issuedAtUnix = Math.round(plaintext.issuedAtBd * 86400);
  const nowUnix = bridge.nowUnix();
  if (issuedAtUnix > nowUnix + LINK_REGISTRATION_FUTURE_SKEW_TOLERANCE_SECONDS) {
    return errorResponse('Stale registration');
  }

  // Cap TTL.
  const ttlSeconds = Math.min(
    Math.max(plaintext.ttlSeconds, 0),
    LINK_MAX_TTL_SECONDS,
  );

  // Bridge-side randomness: bridgeShare (32 bytes), sessionId (16 bytes).
  const bridgeShare = bridge.rng(LINK_SHARE_LENGTH);
  const sessionId = bridge.rng(LINK_SESSION_ID_LENGTH);
  const bridgeIssuedAtUnix = nowUnix;

  // Derive K_session via the bilateral HKDF.
  const { ikm, salt, info, outputByteCount } = buildSessionKeyHkdfInputs({
    clientNonce,
    sessionId,
    clientShare,
    bridgeShare,
  });
  const kSession = Buffer.from(hkdf(sha256, ikm, salt, info, outputByteCount));
  if (kSession.length !== LINK_SESSION_KEY_LENGTH) {
    throw new Error('internal: HKDF returned wrong length');
  }

  // Build canonical transcript and sign with the SEP stand-in.
  const transcript = buildTranscript({
    clientNonce,
    clientPub,
    clientShare,
    sessionId,
    bridgeShare,
    issuedAtBd: plaintext.issuedAtBd,
    bridgeIssuedAtUnix,
    ttlSeconds,
  });
  const transcriptSig = bridge.sep.sign(transcript);

  // Encrypt bridgeShare (32 bytes) back to the client's ephemeral public key
  // using DD-ECIES Basic mode. This is the `responseEnvelope` field.
  const responseEnvelope = encryptBasicEnvelopeToClient(
    bridgeShare,
    clientPub,
    bridge.rng,
  );

  // Bind session to this connection.
  const session: LinkSession = {
    sessionId,
    kSession,
    bridgeIssuedAtUnix,
    expiresAtUnix: bridgeIssuedAtUnix + ttlSeconds,
    ttlSeconds,
    outboundCounter: 0n,
    lastInboundCounter: 0n,
    agentInfo,
  };
  // Re-issuing LINK_REGISTER on the same connection invalidates the prior
  // session per RFC §4.3.
  if (conn.linkSession) {
    bridge.recordAudit({
      kind: 'session_teardown',
      sessionIdHex: conn.linkSession.sessionId.toString('hex'),
      payload: { reason: 'reregister' },
    });
    // Wipe.
    conn.linkSession.kSession.fill(0);
  }
  conn.linkSession = session;

  bridge.recordAudit({
    kind: 'session_init',
    sessionIdHex: sessionId.toString('hex'),
    payload: {
      ttlSeconds,
      agentName: agentInfo.name,
      agentVersion: agentInfo.version,
      agentPlatform: agentInfo.platform,
      transcriptSigPrefixHex: transcriptSig.subarray(0, 16).toString('hex'),
    },
  });

  return jsonResponse({
    ok: true,
    sessionId: sessionId.toString('base64'),
    bridgeIssuedAtUnix,
    ttlSeconds,
    responseEnvelope: responseEnvelope.toString('base64'),
    transcriptSig: transcriptSig.toString('base64'),
  });
}

/** Build a DD-ECIES Basic-mode envelope addressed to `recipientPub`,
 *  carrying `plaintext`. Uses a fresh ephemeral keypair from `rng`. */
function encryptBasicEnvelopeToClient(
  plaintext: Buffer,
  recipientPub: Buffer,
  rng: Rng,
): Buffer {
  // The bridge's response envelope addresses the client's ephemeral
  // secp256k1 public key (clientPub). recipientPub here is 65-byte uncompressed.
  // We generate our own ephemeral, ECDH with the client pub, derive AES key,
  // encrypt plaintext, and assemble Basic-mode wire format.

  // Generate ephemeral secp256k1 key. RNG must produce a valid private key
  // (in [1, n-1]); we retry if needed.
  let ephPriv: Buffer;
  for (;;) {
    ephPriv = rng(32);
    try {
      // @noble/curves throws if ephPriv is out of range.
      secp256k1.getPublicKey(ephPriv, true);
      break;
    } catch {
      continue;
    }
  }
  // Compressed for the wire (33 bytes per RFC §4.5.0).
  const ephPubCompressed = Buffer.from(secp256k1.getPublicKey(ephPriv, true));
  if (ephPubCompressed.length !== ECIES_PUBLIC_KEY_LENGTH) {
    throw new Error('internal: compressed pub key not 33 bytes');
  }

  // ECDH against the client's uncompressed public key.
  const shared33 = secp256k1.getSharedSecret(ephPriv, recipientPub, true);
  const x32 = shared33.subarray(1);
  const aesKey = Buffer.from(
    hkdf(sha256, x32, new Uint8Array(0), ECIES_HKDF_INFO, ECIES_HKDF_OUTPUT_LENGTH),
  );

  // IV and AAD.
  const iv = rng(ECIES_IV_SIZE);
  const aad = Buffer.concat([
    Buffer.from([
      ECIES_VERSION_BYTE,
      ECIES_CIPHER_SUITE_BYTE,
      ECIES_ENCRYPTION_TYPE.BASIC,
    ]),
    ephPubCompressed,
  ]);

  const cipher = createCipheriv('aes-256-gcm', aesKey, iv, {
    authTagLength: ECIES_AUTH_TAG_SIZE,
  });
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([
    Buffer.from([
      ECIES_VERSION_BYTE,
      ECIES_CIPHER_SUITE_BYTE,
      ECIES_ENCRYPTION_TYPE.BASIC,
    ]),
    ephPubCompressed,
    iv,
    tag,
    ct,
  ]);
}

// ────────────────────────────────────────────────────────────────────────────
// LINK_DELIVER (RFC §4.9)
// ────────────────────────────────────────────────────────────────────────────

/**
 * Decode + verify one `LINK_DELIVER` request from a registered shell.
 * BrightLink v1 §4.9: payload arrives as a JSON object with `counter`,
 * `type`, `context`, `iv`, `ciphertext`, `authTag`. The bridge reconstructs
 * the AAD with `dir_tag = 0x01`, decrypts under K_session, advances the
 * inbound counter, and records an audit event.
 */
function handleLinkDeliver(
  req: Record<string, unknown>,
  bridge: BridgeState,
  conn: ConnectionState,
): Buffer {
  const session = conn.linkSession;
  if (!session) {
    return errorResponse('Session not registered on this connection');
  }
  const now = bridge.nowUnix();
  if (now > session.expiresAtUnix) {
    return errorResponse('Session expired');
  }

  // Parse the JSON wire fields. RFC §4.9.1.
  const counterRaw = req['counter'];
  const type = req['type'];
  const contextStr = req['context'];
  const ivB64 = req['iv'];
  const ctB64 = req['ciphertext'];
  const tagB64 = req['authTag'];

  if (
    typeof counterRaw !== 'number' && typeof counterRaw !== 'string' && typeof counterRaw !== 'bigint'
  ) {
    return recordIngestFailed(bridge, session, 'malformed', 'Missing counter');
  }
  if (typeof type !== 'string') {
    return recordIngestFailed(bridge, session, 'malformed', 'Missing type');
  }
  if (typeof contextStr !== 'string') {
    return recordIngestFailed(bridge, session, 'malformed', 'Missing context');
  }
  if (typeof ivB64 !== 'string' || typeof ctB64 !== 'string' || typeof tagB64 !== 'string') {
    return recordIngestFailed(bridge, session, 'malformed', 'Missing iv/ciphertext/authTag');
  }

  const counter = BigInt(counterRaw);
  if (counter < 0n || counter > 0xffff_ffff_ffff_ffffn) {
    return recordIngestFailed(bridge, session, 'malformed', 'Counter out of u64 range');
  }

  // Replay window. RFC §4.6.4.
  if (counter <= session.lastInboundCounter) {
    return recordIngestFailed(bridge, session, 'counter_replayed', 'Counter replayed');
  }
  if (counter > session.lastInboundCounter + BigInt(LINK_COUNTER_REPLAY_WINDOW)) {
    return recordIngestFailed(bridge, session, 'counter_out_of_window', 'Counter out of replay window');
  }

  const iv = tryBase64(ivB64);
  const ct = tryBase64(ctB64);
  const tag = tryBase64(tagB64);
  if (iv === null || ct === null || tag === null) {
    return recordIngestFailed(bridge, session, 'malformed', 'iv/ciphertext/authTag not base64');
  }
  if (iv.length !== LINK_GCM_IV_LENGTH) {
    return recordIngestFailed(bridge, session, 'malformed', `iv must be ${LINK_GCM_IV_LENGTH} bytes`);
  }
  if (tag.length !== LINK_GCM_TAG_LENGTH) {
    return recordIngestFailed(bridge, session, 'malformed', `authTag must be ${LINK_GCM_TAG_LENGTH} bytes`);
  }

  // Reconstruct AAD with the receiver's direction tag.
  const contextBytes = Buffer.from(contextStr, 'utf8');
  const aad = buildDeliverAad({
    dirTag: LINK_DIR_TAG.SHELL_TO_AGENT,
    counter,
    type,
    contextBytes,
  });

  // AES-256-GCM open.
  let plaintext: Buffer;
  try {
    const decipher = createDecipheriv('aes-256-gcm', session.kSession, iv, {
      authTagLength: LINK_GCM_TAG_LENGTH,
    });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    return recordIngestFailed(bridge, session, 'auth_failed', 'AES-GCM authentication failed');
  }

  // Decode body; honor §4.6 nota-bene type/context overrides.
  let resolvedType = type;
  let resolvedContext = contextStr;
  try {
    const body = JSON.parse(plaintext.toString('utf8'));
    if (typeof body === 'object' && body !== null) {
      const b = body as Record<string, unknown>;
      if (typeof b['type'] === 'string') resolvedType = b['type'] as string;
      if (typeof b['context'] === 'string') resolvedContext = b['context'] as string;
    }
  } catch {
    // Non-JSON body: accept as-is.
  }

  session.lastInboundCounter = counter;
  bridge.recordAudit({
    kind: 'link_deliver_ok',
    sessionIdHex: session.sessionId.toString('hex'),
    payload: {
      type: resolvedType,
      context: resolvedContext,
      counter: Number(counter),
    },
  });

  return jsonResponse({ ok: true, type: resolvedType, context: resolvedContext });
}

function recordIngestFailed(
  bridge: BridgeState,
  session: LinkSession,
  reason: string,
  errorMessage: string,
): Buffer {
  bridge.recordAudit({
    kind: 'link_deliver_failed',
    sessionIdHex: session.sessionId.toString('hex'),
    payload: { reason },
  });
  return errorResponse(errorMessage);
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

function jsonResponse(obj: Record<string, unknown>): Buffer {
  return Buffer.from(JSON.stringify(obj));
}

function errorResponse(message: string): Buffer {
  return jsonResponse({ error: message });
}

function tryBase64(s: string): Buffer | null {
  try {
    const b = Buffer.from(s, 'base64');
    // Empty result indicates a non-base64 input.
    if (s.length > 0 && b.length === 0) return null;
    return b;
  } catch {
    return null;
  }
}

function fingerprint(pub: Buffer): string {
  // First 8 bytes of SHA-256 over the public key, formatted "AA:BB:..."
  // matching EBP/1 §4.8.
  const hash = require('node:crypto').createHash('sha256').update(pub).digest();
  return [...hash.subarray(0, 8)]
    .map((b: number) => b.toString(16).padStart(2, '0'))
    .join(':')
    .toUpperCase();
}


// ────────────────────────────────────────────────────────────────────────────
// LINK_GEO_* handlers (RFC §9)
//
// Each handler:
//   1. Verifies the connection has a registered LINK_REGISTER session
//      (RFC §9.7 — `geo: session not registered` if absent).
//   2. Pulls the connection's peer attestation (set by socket-server at
//      accept-time; defaults to unsigned if not set).
//   3. Delegates to `LinkGeoEngine` for ACL gating, prompt routing, and
//      data assembly.
//   4. Wraps the engine's `GeoResult<T>` into the JSON response shape
//      defined in §9.{1..5}.
// ────────────────────────────────────────────────────────────────────────────

function attestationFor(conn: ConnectionState, bridge: BridgeState): PeerAttestation {
  // The socket-server normally populates `conn.attestation` at accept-time.
  // In direct unit tests that bypass the server we fall back to pulling a
  // fresh attestation from the provider on every request.
  if (conn.attestation === null) {
    conn.attestation = bridge.peerAttestation.attest();
  }
  return conn.attestation;
}

async function handleLinkGeoStatus(
  _req: Record<string, unknown>,
  bridge: BridgeState,
  conn: ConnectionState,
): Promise<Buffer> {
  if (!conn.linkSession) {
    return errorResponse(LINK_GEO_ERRORS.SESSION_NOT_REGISTERED);
  }
  const attestation = attestationFor(conn, bridge);
  const r = bridge.geo.status(attestation);
  if (!r.ok) return errorResponse(r.error);
  return jsonResponse({
    ok: true,
    alive: r.value.alive,
    engine_kind: r.value.engineKind,
    fix_age_seconds: r.value.fixAgeSeconds,
    accuracy_m: r.value.accuracyM,
  });
}

async function handleLinkGeoProximity(
  req: Record<string, unknown>,
  bridge: BridgeState,
  conn: ConnectionState,
): Promise<Buffer> {
  if (!conn.linkSession) {
    return errorResponse(LINK_GEO_ERRORS.SESSION_NOT_REGISTERED);
  }
  const zoneId = req['zone'];
  if (typeof zoneId !== 'string' || zoneId.length === 0) {
    return errorResponse('Missing zone');
  }
  const attestation = attestationFor(conn, bridge);
  const r = await bridge.geo.proximity(attestation, zoneId);
  if (!r.ok) return errorResponse(r.error);
  return jsonResponse({
    ok: true,
    in_zone: r.value.inZone,
    brightdate: r.value.brightdate,
  });
}

async function handleLinkGeoZone(
  _req: Record<string, unknown>,
  bridge: BridgeState,
  conn: ConnectionState,
): Promise<Buffer> {
  if (!conn.linkSession) {
    return errorResponse(LINK_GEO_ERRORS.SESSION_NOT_REGISTERED);
  }
  const attestation = attestationFor(conn, bridge);
  const r = await bridge.geo.zone(attestation);
  if (!r.ok) return errorResponse(r.error);
  return jsonResponse({
    ok: true,
    zone: r.value.zone,
    dwell_seconds: r.value.dwellSeconds,
    brightdate: r.value.brightdate,
  });
}

async function handleLinkGeoGet(
  req: Record<string, unknown>,
  bridge: BridgeState,
  conn: ConnectionState,
): Promise<Buffer> {
  if (!conn.linkSession) {
    return errorResponse(LINK_GEO_ERRORS.SESSION_NOT_REGISTERED);
  }
  const formatRaw = req['format'] ?? 'both';
  if (
    formatRaw !== 'wgs84' &&
    formatRaw !== 'brightspace' &&
    formatRaw !== 'both'
  ) {
    return errorResponse(LINK_GEO_ERRORS.FORMAT_INVALID);
  }
  const attestation = attestationFor(conn, bridge);
  const r = await bridge.geo.get(attestation, formatRaw as CoordinateFormat);
  if (!r.ok) return errorResponse(r.error);
  return jsonResponse({
    ok: true,
    position: r.value.position,
    accuracy_m: r.value.accuracy_m,
    brightdate: r.value.brightdate,
  });
}

async function handleLinkGeoRefresh(
  req: Record<string, unknown>,
  bridge: BridgeState,
  conn: ConnectionState,
): Promise<Buffer> {
  if (!conn.linkSession) {
    return errorResponse(LINK_GEO_ERRORS.SESSION_NOT_REGISTERED);
  }
  const timeoutRaw = req['timeout_seconds'];
  const timeoutSeconds =
    typeof timeoutRaw === 'number' && Number.isFinite(timeoutRaw) && timeoutRaw > 0
      ? timeoutRaw
      : 10;
  const attestation = attestationFor(conn, bridge);
  const r = await bridge.geo.refresh(attestation, timeoutSeconds);
  if (!r.ok) return errorResponse(r.error);
  return jsonResponse({
    ok: true,
    fix_age_seconds: r.value.fixAgeSeconds,
    accuracy_m: r.value.accuracyM,
  });
}
