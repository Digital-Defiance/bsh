/**
 * `mock-bsh-client` — a BrightLink v1-aware bsh shell, in TypeScript, in-process.
 *
 * Speaks EBP/1 + BrightLink v1 to a BrightNexus (real or `mock-brightnexus`).
 * Generates fresh client material per registration, performs the
 * LINK_REGISTER handshake, derives K_session, verifies the bridge's
 * SEP-anchored transcript signature, and exposes the LINK_DELIVER
 * surface that bsh's `bsh-inject` builtin uses.
 *
 * Public API (intentionally thin — keep the surface small):
 *
 *   const c = new MockBshClient();
 *   await c.connect(socketPath);
 *
 *   await c.heartbeat();
 *   const pub = await c.getPublicKey();
 *   const sepPub = await c.getEnclavePublicKey();
 *   await c.register();                         // LINK_REGISTER
 *   c.session                                   // LinkClientSession | null
 *   await c.ingestCredential({ type, context, body })  // → LINK_DELIVER
 *   await c.subscribePush(handler)              // LINK_PUSH subscribe (reserved)
 *   await c.disconnect();
 *
 * Sender direction is always Shell → Agent (dir_tag = 0x01).
 * Receiver direction is always Agent → Shell (dir_tag = 0x02).
 */

import { Buffer } from 'node:buffer';
import { randomBytes, createCipheriv, createDecipheriv, createVerify, createPublicKey } from 'node:crypto';

import { secp256k1 } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

import {
  EBP1_COMMANDS,
  LINK_COMMANDS,
  LINK_PROTOCOL_VERSION,
  LINK_CLIENT_NONCE_LENGTH,
  LINK_SHARE_LENGTH,
  LINK_SESSION_KEY_LENGTH,
  LINK_GCM_IV_LENGTH,
  LINK_GCM_TAG_LENGTH,
  LINK_DIR_TAG,
  buildPushAad,
  buildSessionKeyHkdfInputs,
  buildTranscript,
  buildDeliverAad,
  ECIES_HKDF_INFO,
  ECIES_HKDF_OUTPUT_LENGTH,
  ECIES_IV_SIZE,
  ECIES_AUTH_TAG_SIZE,
  ECIES_VERSION_BYTE,
  ECIES_CIPHER_SUITE_BYTE,
  ECIES_ENCRYPTION_TYPE,
} from '../spec/index.js';
import { TestClient } from '../shared/test-client.js';
import type { MockBshClientOptions, LinkClientSession } from './types.js';

export class MockBshClient {
  private readonly transport = new TestClient();
  private readonly options: MockBshClientOptions;
  private readonly rng: (n: number) => Buffer;
  private readonly nowUnix: () => number;

  /** The current BrightLink session, or null if not registered. */
  session: LinkClientSession | null = null;

  /** Pinned SEP public key from a prior connection (TOFU per RFC §4.5.5).
   *  If set, registration verifies the bridge's SEP public key matches this.
   *  If null, the client accepts whatever the bridge presents and pins it. */
  pinnedSepPublicKey: Buffer | null = null;

  /** Cached bridge ECIES public key (refreshed on demand). */
  private cachedBridgePub: Buffer | null = null;

  constructor(options: MockBshClientOptions = {}) {
    this.options = options;
    this.rng = options.rng ?? ((n: number) => Buffer.from(randomBytes(n)));
    this.nowUnix = options.nowUnix ?? (() => Math.floor(Date.now() / 1000));
  }

  // ──────────────────────────────────────────────────────────────────
  // Connection lifecycle
  // ──────────────────────────────────────────────────────────────────

  async connect(socketPath: string): Promise<void> {
    await this.transport.connect(socketPath);
  }

  async disconnect(): Promise<void> {
    await this.transport.disconnect();
    this.cachedBridgePub = null;
    if (this.session) {
      this.session.kSession.fill(0);
      this.session = null;
    }
  }

  // ──────────────────────────────────────────────────────────────────
  // EBP/1 surface — minimal set the mock needs
  // ──────────────────────────────────────────────────────────────────

  async heartbeat(): Promise<{ ok: boolean; timestamp: string; service: string }> {
    const r = await this.send({ cmd: EBP1_COMMANDS.HEARTBEAT });
    if (r['error']) throw new MockBshError(String(r['error']));
    return r as never;
  }

  async getPublicKey(skipCache = false): Promise<Buffer> {
    if (!skipCache && this.cachedBridgePub) return this.cachedBridgePub;
    const r = await this.send({ cmd: EBP1_COMMANDS.GET_PUBLIC_KEY });
    if (r['error']) throw new MockBshError(String(r['error']));
    const buf = Buffer.from(r['publicKey'] as string, 'base64');
    this.cachedBridgePub = buf;
    return buf;
  }

  async getEnclavePublicKey(): Promise<Buffer> {
    const r = await this.send({ cmd: EBP1_COMMANDS.GET_ENCLAVE_PUBLIC_KEY });
    if (r['error']) throw new MockBshError(String(r['error']));
    return Buffer.from(r['publicKey'] as string, 'base64');
  }

  // ──────────────────────────────────────────────────────────────────
  // LINK_REGISTER — RFC §4.5
  // ──────────────────────────────────────────────────────────────────

  /**
   * Perform a LINK_REGISTER handshake. Caller must already have called
   * `connect()`. On success, `session` is populated and LINK_DELIVER emit
   * are usable. On failure, throws `MockBshError` and `session` remains null.
   */
  async register(args: {
    /** Requested TTL in seconds. Defaults to 1h. Bridge caps at 8h. */
    ttlSeconds?: number;
    /** Override the BrightDate scalar in the §4.5.1 envelope. Tests use this
     *  to reproduce vectors. Defaults to a value derived from `nowUnix`. */
    issuedAtBd?: number;
    /** Override the client ephemeral private key (32 random bytes). */
    ephemeralPrivKey?: Buffer;
    /** Override the clientNonce (16 bytes). */
    clientNonce?: Buffer;
    /** Override the clientShare (32 bytes). */
    clientShare?: Buffer;
  } = {}): Promise<LinkClientSession> {
    if (this.session) {
      throw new MockBshError('Already registered on this connection');
    }

    // Fetch bridge keys.
    const bridgePub = await this.getPublicKey();
    const sepPub = await this.getEnclavePublicKey();

    // TOFU pinning: if the client has a prior pinned SEP key, the new one
    // MUST match it byte-for-byte. RFC §4.5.5.
    if (this.pinnedSepPublicKey && !this.pinnedSepPublicKey.equals(sepPub)) {
      throw new MockBshError(
        'SEP public key changed since last registration (pinned mismatch)',
      );
    }

    // Generate client material.
    const clientNonce = args.clientNonce ?? this.rng(LINK_CLIENT_NONCE_LENGTH);
    const clientShare = args.clientShare ?? this.rng(LINK_SHARE_LENGTH);
    const ephPriv = args.ephemeralPrivKey ?? this.options.ephemeralPrivKey ?? this.rng(32);
    const ephPub = Buffer.from(secp256k1.getPublicKey(ephPriv, false));
    if (ephPub.length !== 65) {
      throw new MockBshError('internal: ephemeral pub not 65 bytes');
    }

    // Build §4.5.1 envelope plaintext.
    const issuedAtBd = args.issuedAtBd ?? this.nowUnix() / 86400;
    const ttlSeconds = args.ttlSeconds ?? 3600;
    const agent = this.options.agentInfo ?? {
      name: 'mock-bsh-client',
      version: '0.1.0',
      platform: `node-${process.platform}-${process.arch}`,
    };
    const plaintext = Buffer.from(
      JSON.stringify({
        v: LINK_PROTOCOL_VERSION,
        clientPub: ephPub.toString('base64'),
        clientShare: clientShare.toString('base64'),
        issuedAtBd,
        ttlSeconds,
        agent,
      }),
    );

    // ECIES-encrypt to the bridge's persistent secp256k1 public key.
    const envelope = encryptBasicEnvelope(plaintext, bridgePub, this.rng);

    // Send LINK_REGISTER.
    const resp = await this.send({
      cmd: LINK_COMMANDS.REGISTER,
      protocolVersion: LINK_PROTOCOL_VERSION,
      clientNonce: clientNonce.toString('base64'),
      envelope: envelope.toString('base64'),
    });
    if (resp['error']) throw new MockBshError(String(resp['error']));
    if (resp['ok'] !== true) throw new MockBshError('registration response missing ok flag');

    // Parse response.
    const sessionIdStr = resp['sessionId'];
    const respEnvelopeStr = resp['responseEnvelope'];
    const transcriptSigStr = resp['transcriptSig'];
    const bridgeIssuedAtUnix = resp['bridgeIssuedAtUnix'];
    const grantedTtlSeconds = resp['ttlSeconds'];

    if (
      typeof sessionIdStr !== 'string' ||
      typeof respEnvelopeStr !== 'string' ||
      typeof transcriptSigStr !== 'string' ||
      typeof bridgeIssuedAtUnix !== 'number' ||
      typeof grantedTtlSeconds !== 'number'
    ) {
      throw new MockBshError('registration response is malformed');
    }

    const sessionId = Buffer.from(sessionIdStr, 'base64');
    const transcriptSig = Buffer.from(transcriptSigStr, 'base64');
    const responseEnvelope = Buffer.from(respEnvelopeStr, 'base64');
    if (sessionId.length !== 16) {
      throw new MockBshError(`sessionId not 16 bytes (got ${sessionId.length})`);
    }

    // Decrypt the responseEnvelope to recover bridgeShare.
    const bridgeShare = decryptBasicEnvelope(responseEnvelope, ephPriv);
    if (bridgeShare.length !== LINK_SHARE_LENGTH) {
      throw new MockBshError(
        `bridgeShare not ${LINK_SHARE_LENGTH} bytes (got ${bridgeShare.length})`,
      );
    }

    // Derive K_session.
    const { ikm, salt, info, outputByteCount } = buildSessionKeyHkdfInputs({
      clientNonce,
      sessionId,
      clientShare,
      bridgeShare,
    });
    const kSession = Buffer.from(hkdf(sha256, ikm, salt, info, outputByteCount));
    if (kSession.length !== LINK_SESSION_KEY_LENGTH) {
      throw new MockBshError('internal: K_session derivation produced wrong length');
    }

    // Verify the SEP-signed transcript.
    const transcript = buildTranscript({
      clientNonce,
      clientPub: ephPub,
      clientShare,
      sessionId,
      bridgeShare,
      issuedAtBd,
      bridgeIssuedAtUnix,
      ttlSeconds: grantedTtlSeconds,
    });
    if (!verifySepSignature(sepPub, transcript, transcriptSig)) {
      throw new MockBshError('transcript signature verification failed');
    }

    // Pin the SEP public key on first successful registration (TOFU).
    if (!this.pinnedSepPublicKey) {
      this.pinnedSepPublicKey = Buffer.from(sepPub);
    }

    this.session = {
      sessionId,
      kSession,
      bridgeIssuedAtUnix,
      ttlSeconds: grantedTtlSeconds,
      expiresAtUnix: bridgeIssuedAtUnix + grantedTtlSeconds,
      sepPublicKey: Buffer.from(sepPub),
      outboundCounter: 0n,
      lastInboundCounter: 0n,
    };

    // Wipe sensitive intermediates.
    bridgeShare.fill(0);
    ephPriv.fill(0);

    return this.session;
  }

  // ──────────────────────────────────────────────────────────────────
  // LINK_PUSH subscription
  // ──────────────────────────────────────────────────────────────────

  /**
   * Subscribe to bridge → shell push events on the established session.
   * Each pushed event carries an Agent → Shell payload encrypted under
   * `K_session` with `dir_tag = 0x02`. The handler decrypts and dispatches.
   *
   * Returns once the subscription handshake's "subscribed" frame arrives.
   */
  async subscribePush(handlers: {
    onPayload: (p: { counter: bigint; type: string; contextBytes: Buffer; payload: Buffer }) => void;
    onError?: (err: Error, raw: unknown) => void;
    /** Event names to subscribe to. Defaults to `["zone-transition"]`. */
    events?: string[];
  }): Promise<void> {
    const session = this.requireSession();

    this.transport.pushHandler = (event) => {
      try {
        const parsed = this.openPushFrame(event, session);
        if (parsed !== null) handlers.onPayload(parsed);
      } catch (err) {
        if (handlers.onError) handlers.onError(err as Error, event);
        else throw err;
      }
    };

    const r = await this.send({
      cmd: LINK_COMMANDS.PUSH,
      subscribe: handlers.events ?? ['zone-transition'],
    });
    if (r['error']) throw new MockBshError(String(r['error']));
  }

  /** Disconnect-as-unsubscribe is the §10.4 model — there is no explicit
   *  unsubscribe verb. This shim is kept for source compatibility but
   *  just clears the handler; the real teardown happens on disconnect. */
  async unsubscribePush(): Promise<void> {
    this.transport.pushHandler = null;
  }

  /**
   * Verify and decrypt an Agent → Shell push event frame (§10.2). Returns
   * null for the subscribe-ack frame `{ok:true, subscribed:[...]}`. Throws
   * on auth failure or counter-window violations.
   */
  private openPushFrame(
    event: Record<string, unknown>,
    session: LinkClientSession,
  ): { counter: bigint; eventName: string; payload: Buffer } | null {
    // The subscribe-ack frame has an `ok:true` and a `subscribed` array;
    // it isn't a push event.
    if (event['ok'] === true && Array.isArray(event['subscribed'])) {
      return null;
    }
    const eventName = event['event'];
    const counterRaw = event['counter'];
    const ivB64 = event['iv'];
    const ctB64 = event['ciphertext'];
    const tagB64 = event['authTag'];
    if (
      typeof eventName !== 'string'
      || (typeof counterRaw !== 'number' && typeof counterRaw !== 'string' && typeof counterRaw !== 'bigint')
      || typeof ivB64 !== 'string'
      || typeof ctB64 !== 'string'
      || typeof tagB64 !== 'string'
    ) {
      throw new Error('malformed push event');
    }
    const counter = BigInt(counterRaw);
    if (counter <= session.lastInboundCounter) {
      throw new Error(`push counter replayed (${counter} <= ${session.lastInboundCounter})`);
    }
    const iv = Buffer.from(ivB64, 'base64');
    const ct = Buffer.from(ctB64, 'base64');
    const tag = Buffer.from(tagB64, 'base64');
    const aad = buildPushAad({ counter, event: eventName });
    const decipher = createDecipheriv('aes-256-gcm', session.kSession, iv, {
      authTagLength: tag.length,
    });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    const payload = Buffer.concat([decipher.update(ct), decipher.final()]);
    session.lastInboundCounter = counter;
    return { counter, eventName, payload };
  }

  // ──────────────────────────────────────────────────────────────────
  // LINK_DELIVER (RFC §4.9) — Shell → Agent credential delivery
  // ──────────────────────────────────────────────────────────────────

  /**
   * Encrypt a credential body under the established `K_session` and send
   * it to the bridge via the `LINK_DELIVER` command. The bridge decrypts,
   * parses the JSON body as an `BrightLinkPayload`, and stores it in its
   * `EphemeralStore` for menu-bar display.
   *
   * Returns the bridge's acknowledgement (which echoes `type` and `context`).
   *
   * `body` is JSON-stringified before encryption. The `type` and `context`
   * arguments are placed BOTH on the wire (so the bridge knows the AAD)
   * and inside the encrypted body (so it survives any wire-level
   * confidentiality leak; the body-side values win on resolution).
   */
  async ingestCredential(args: {
    type: string;
    context: string;
    body: Record<string, unknown>;
  }): Promise<{ type: string; context: string }> {
    const session = this.requireSession();

    const fullBody = {
      type: args.type,
      context: args.context,
      ...args.body,
    };
    const plaintext = Buffer.from(JSON.stringify(fullBody), 'utf8');

    // Allocate the next outbound counter.
    const counter = session.outboundCounter + 1n;

    // Build AAD with dir_tag = 0x01 (Shell → Agent).
    const contextBytes = Buffer.from(args.context, 'utf8');
    const aad = buildDeliverAad({
      dirTag: LINK_DIR_TAG.SHELL_TO_AGENT,
      counter,
      type: args.type,
      contextBytes,
    });

    // Fresh IV.
    const iv = this.rng(LINK_GCM_IV_LENGTH);
    const cipher = createCipheriv('aes-256-gcm', session.kSession, iv, {
      authTagLength: LINK_GCM_TAG_LENGTH,
    });
    cipher.setAAD(aad);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    const r = await this.send({
      cmd: LINK_COMMANDS.DELIVER,
      counter: Number(counter),
      type: args.type,
      context: args.context,
      iv: iv.toString('base64'),
      ciphertext: ct.toString('base64'),
      authTag: tag.toString('base64'),
    });
    if (r['error']) throw new MockBshError(String(r['error']));

    // Counter advances only on a successful delivery.
    session.outboundCounter = counter;
    return {
      type: String(r['type']),
      context: String(r['context']),
    };
  }

  // ──────────────────────────────────────────────────────────────────
  // Plumbing
  // ──────────────────────────────────────────────────────────────────

  /** Raw send — primarily for tests that want to exercise the EBP/1
   *  surface beyond what the typed methods cover. */
  send(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.transport.send(payload);
  }

  private requireSession(): LinkClientSession {
    if (!this.session) {
      throw new MockBshError('not registered — call register() first');
    }
    return this.session;
  }
}

// ──────────────────────────────────────────────────────────────────────────

export class MockBshError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MockBshError';
  }
}

// ──────────────────────────────────────────────────────────────────────────
// Helpers — these mirror the bridge-side logic but are independently
// derived so the mocks aren't sharing crypto code with each other.
// ──────────────────────────────────────────────────────────────────────────

/** Encrypt `plaintext` to a recipient's 65-byte uncompressed secp256k1
 *  public key, producing a DD-ECIES Basic-mode envelope. */
function encryptBasicEnvelope(
  plaintext: Buffer,
  recipientPub: Buffer,
  rng: (n: number) => Buffer,
): Buffer {
  // Generate ephemeral key. Retry on (vanishingly improbable) out-of-range scalar.
  let ephPriv: Buffer;
  for (;;) {
    ephPriv = rng(32);
    try {
      secp256k1.getPublicKey(ephPriv, true);
      break;
    } catch {
      continue;
    }
  }
  const ephPubCompressed = Buffer.from(secp256k1.getPublicKey(ephPriv, true));
  const shared33 = secp256k1.getSharedSecret(ephPriv, recipientPub, true);
  const x32 = shared33.subarray(1);
  const aesKey = Buffer.from(
    hkdf(sha256, x32, new Uint8Array(0), ECIES_HKDF_INFO, ECIES_HKDF_OUTPUT_LENGTH),
  );
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

/** Inverse of `encryptBasicEnvelope`. Given a 32-byte private key and a
 *  Basic-mode envelope addressed to it, return the plaintext. */
function decryptBasicEnvelope(envelope: Buffer, recipientPriv: Buffer): Buffer {
  if (envelope.length < 64) {
    throw new MockBshError('responseEnvelope too short');
  }
  if (envelope[0] !== ECIES_VERSION_BYTE) throw new MockBshError('bad version');
  if (envelope[1] !== ECIES_CIPHER_SUITE_BYTE) throw new MockBshError('bad cipher suite');
  if (envelope[2] !== ECIES_ENCRYPTION_TYPE.BASIC) {
    throw new MockBshError('responseEnvelope must be Basic mode');
  }
  const ephPub = envelope.subarray(3, 36); // 33 bytes compressed
  const iv = envelope.subarray(36, 48);
  const tag = envelope.subarray(48, 64);
  const ct = envelope.subarray(64);

  const shared33 = secp256k1.getSharedSecret(recipientPriv, ephPub, true);
  const x32 = shared33.subarray(1);
  const aesKey = Buffer.from(
    hkdf(sha256, x32, new Uint8Array(0), ECIES_HKDF_INFO, ECIES_HKDF_OUTPUT_LENGTH),
  );
  const aad = Buffer.concat([
    Buffer.from([envelope[0]!, envelope[1]!, envelope[2]!]),
    ephPub,
  ]);
  const decipher = createDecipheriv('aes-256-gcm', aesKey, iv, {
    authTagLength: ECIES_AUTH_TAG_SIZE,
  });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

/** Verify a DER-encoded ECDSA-over-P-256 signature against the SEP public
 *  key (65-byte uncompressed). The SEP signs SHA-256(transcript) per
 *  Apple CryptoKit's `priv.signature(for:)` and EBP/1 §4.9. We use Node's
 *  createVerify which hashes internally, matching that behavior. */
function verifySepSignature(
  sepPubUncompressed: Buffer,
  transcript: Buffer,
  signatureDer: Buffer,
): boolean {
  if (sepPubUncompressed.length !== 65 || sepPubUncompressed[0] !== 0x04) {
    return false;
  }
  const x = sepPubUncompressed.subarray(1, 33);
  const y = sepPubUncompressed.subarray(33, 65);
  const jwk = {
    kty: 'EC' as const,
    crv: 'P-256' as const,
    x: x.toString('base64url'),
    y: y.toString('base64url'),
  };
  const pubKey = createPublicKey({ key: jwk, format: 'jwk' });
  const verifier = createVerify('SHA256');
  verifier.update(transcript);
  return verifier.verify({ key: pubKey, dsaEncoding: 'der' }, signatureDer);
}

// Re-export commonly-used types so callers can `import { MockBshClient,
// LinkClientSession } from '@harness/mock-bsh-client'`.
export type { LinkClientSession, MockBshClientOptions } from './types.js';
export { discoverSocketPath, listDiscoveryCandidates } from './discovery.js';
