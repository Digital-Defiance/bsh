/**
 * mock-brightnexus unit tests.
 *
 * These exercise the EBP/1 surface and the BrightLink v1 LINK_REGISTER + LINK_PUSH
 * surface against the in-process mock. They do NOT involve any real Apple
 * hardware, the real Swift bridge, or the real enclave-bridge-client.
 *
 * If a test in this file fails, the mock has drifted from the spec. If the
 * mock matches the spec but a real implementation fails interop, the bug is
 * in that real implementation.
 *
 * Test structure: each `describe` block sets up a fresh MockBrightNexus + a
 * fresh TestClient, runs assertions, and tears them down. Sockets bind under
 * the OS temp dir with a random suffix so parallel tests don't collide.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { Buffer } from 'node:buffer';
import { createCipheriv } from 'node:crypto';

import { secp256k1 } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { createVerify, createPublicKey } from 'node:crypto';

import { MockBrightNexus } from '../../src/mock-brightnexus/index.js';
import { TestClient, uniqueSocketPath } from '../../src/shared/test-client.js';
import {
  EBP1_COMMANDS,
  EBP1_ERRORS,
  EBP1_KEY_IDS,
  EBP1_KEY_TYPES,
  EBP1_SERVICE_NAME,
  BRIGHTNEXUS_APP_NAME,
  LINK_COMMANDS,
  LINK_PROTOCOL_VERSION,
  LINK_ERROR_NOT_IMPLEMENTED_SUFFIX,
  LINK_CLIENT_NONCE_LENGTH,
  LINK_SHARE_LENGTH,
  LINK_SESSION_ID_LENGTH,
  LINK_SESSION_KEY_LENGTH,
  LINK_MAX_TTL_SECONDS,
  buildSessionKeyHkdfInputs,
  buildTranscript,
  ECIES_HKDF_INFO,
  ECIES_HKDF_OUTPUT_LENGTH,
  ECIES_IV_SIZE,
  ECIES_AUTH_TAG_SIZE,
  ECIES_VERSION_BYTE,
  ECIES_CIPHER_SUITE_BYTE,
  ECIES_ENCRYPTION_TYPE,
} from '../../src/spec/index.js';
import {
  DD_ECIES_TEST_PRIVATE_KEY_HEX,
  DD_ECIES_TEST_PUBLIC_KEY_COMPRESSED_HEX,
  DD_ECIES_TEST_BASIC_ENVELOPE_HEX,
  DD_ECIES_TEST_PLAINTEXT_HEX,
} from '../../src/shared/known-answer-vectors.js';

const hex = (s: string) => Buffer.from(s, 'hex');

// ─── Test rig setup/teardown ──────────────────────────────────────────────

let mock: MockBrightNexus;
let client: TestClient;

async function setUp(opts: ConstructorParameters<typeof MockBrightNexus>[0] = {}): Promise<void> {
  mock = new MockBrightNexus(opts);
  await mock.start(uniqueSocketPath());
  client = new TestClient();
  await client.connect(mock.getSocketPath());
}

async function tearDown(): Promise<void> {
  await client.disconnect();
  await mock.stop();
}

// ─── EBP/1 core surface ───────────────────────────────────────────────────

describe('mock-brightnexus EBP/1 core surface', () => {
  beforeEach(async () => { await setUp(); });
  afterEach(async () => { await tearDown(); });

  it('HEARTBEAT returns ok + service name', async () => {
    const r = await client.send({ cmd: EBP1_COMMANDS.HEARTBEAT });
    expect(r['ok']).toBe(true);
    expect(r['service']).toBe(EBP1_SERVICE_NAME);
    expect(typeof r['timestamp']).toBe('string');
  });

  it('VERSION/INFO advertises the new BrightNexus app field + brightlinkProtocolVersion', async () => {
    const r = await client.send({ cmd: EBP1_COMMANDS.VERSION });
    expect(r['app']).toBe(BRIGHTNEXUS_APP_NAME);
    expect(r['brightlinkProtocolVersion']).toBe(LINK_PROTOCOL_VERSION);
    expect(r['platform']).toBeDefined();
    // INFO is an alias of VERSION per EBP/1 §4.2.
    const r2 = await client.send({ cmd: EBP1_COMMANDS.INFO });
    expect(r2['app']).toBe(BRIGHTNEXUS_APP_NAME);
  });

  it('STATUS reflects peerPublicKeySet false initially, true after SET_PEER_PUBLIC_KEY', async () => {
    const before = await client.send({ cmd: EBP1_COMMANDS.STATUS });
    expect(before['peerPublicKeySet']).toBe(false);
    expect(before['enclaveKeyAvailable']).toBe(true);

    // Send a fabricated peer key (we don't validate cryptographic correctness
    // of the bytes server-side per RFC §4.7).
    const fakePeer = Buffer.alloc(65, 0x04).toString('base64');
    const setResp = await client.send({
      cmd: EBP1_COMMANDS.SET_PEER_PUBLIC_KEY,
      publicKey: fakePeer,
    });
    expect(setResp['ok']).toBe(true);

    const after = await client.send({ cmd: EBP1_COMMANDS.STATUS });
    expect(after['peerPublicKeySet']).toBe(true);
  });

  it('SET_PEER_PUBLIC_KEY rejects missing field with the spec error', async () => {
    const r = await client.send({ cmd: EBP1_COMMANDS.SET_PEER_PUBLIC_KEY });
    expect(r['error']).toBe(EBP1_ERRORS.MISSING_OR_INVALID_PUBLIC_KEY);
  });

  it('LIST_KEYS returns both reserved keys with the documented shape', async () => {
    const r = await client.send({ cmd: EBP1_COMMANDS.LIST_KEYS });
    const keys = r['keys'] as Array<Record<string, unknown>>;
    expect(keys).toHaveLength(2);
    const eciesKey = keys.find((k) => k['id'] === EBP1_KEY_IDS.ECIES_SECP256K1)!;
    expect(eciesKey['type']).toBe(EBP1_KEY_TYPES.SECP256K1);
    expect(eciesKey['isSecureEnclave']).toBe(false);
    const sepKey = keys.find((k) => k['id'] === EBP1_KEY_IDS.SECURE_ENCLAVE_P256)!;
    expect(sepKey['type']).toBe(EBP1_KEY_TYPES.SECURE_ENCLAVE_P256);
    expect(sepKey['isSecureEnclave']).toBe(true);
    // Fingerprint format: AA:BB:CC:DD:EE:FF:GG:HH (8 hex bytes, uppercase, colon-separated).
    expect(eciesKey['publicKeyFingerprint']).toMatch(/^[0-9A-F]{2}(:[0-9A-F]{2}){7}$/);
  });

  it('METRICS returns uptimeSeconds + the legacy service name', async () => {
    const r = await client.send({ cmd: EBP1_COMMANDS.METRICS });
    expect(typeof r['uptimeSeconds']).toBe('number');
    expect(r['service']).toBe(EBP1_SERVICE_NAME);
    expect(r['requestCounters']).toEqual({});
  });

  it('GET_PUBLIC_KEY returns the 65-byte uncompressed bridge key', async () => {
    const r = await client.send({ cmd: EBP1_COMMANDS.GET_PUBLIC_KEY });
    const buf = Buffer.from(r['publicKey'] as string, 'base64');
    expect(buf.length).toBe(65);
    expect(buf[0]).toBe(0x04);
  });

  it('GET_ENCLAVE_PUBLIC_KEY returns the 65-byte uncompressed SEP key', async () => {
    const r = await client.send({ cmd: EBP1_COMMANDS.GET_ENCLAVE_PUBLIC_KEY });
    const buf = Buffer.from(r['publicKey'] as string, 'base64');
    expect(buf.length).toBe(65);
    expect(buf[0]).toBe(0x04);
  });

  it('ENCLAVE_GENERATE_KEY and ENCLAVE_ROTATE_KEY return their reserved error strings', async () => {
    const a = await client.send({ cmd: EBP1_COMMANDS.ENCLAVE_GENERATE_KEY });
    expect(a['error']).toBe(EBP1_ERRORS.ENCLAVE_GENERATE_KEY_NOT_IMPLEMENTED);
    const b = await client.send({ cmd: EBP1_COMMANDS.ENCLAVE_ROTATE_KEY });
    expect(b['error']).toBe(EBP1_ERRORS.ENCLAVE_ROTATE_KEY_NOT_SUPPORTED);
  });

  it('Unknown commands return "Unknown command: <cmd>"', async () => {
    const r = await client.send({ cmd: 'NONSENSE' });
    expect(r['error']).toBe(`${EBP1_ERRORS.UNKNOWN_COMMAND_PREFIX}NONSENSE`);
  });

  it('Missing cmd field returns "Invalid request format"', async () => {
    const r = await client.send({ notACmd: 'oops' });
    expect(r['error']).toBe(EBP1_ERRORS.INVALID_REQUEST_FORMAT);
  });
});

// ─── ENCLAVE_DECRYPT — exercise against the DD-ECIES §18.6 known-answer ───

describe('mock-brightnexus ENCLAVE_DECRYPT', () => {
  it('decrypts the canonical DD-ECIES §18.6 envelope when the bridge holds the matching private key', async () => {
    // Pin the bridge's persistent secp256k1 key to the DD-ECIES test private
    // key. Then send the documented Basic-mode envelope and verify the
    // bridge returns the documented plaintext.
    await setUp({ secp256k1Priv: hex(DD_ECIES_TEST_PRIVATE_KEY_HEX) });
    try {
      // Sanity: confirm GET_PUBLIC_KEY matches the documented compressed form
      // (after re-compression — the bridge returns 65-byte uncompressed).
      const pubResp = await client.send({ cmd: EBP1_COMMANDS.GET_PUBLIC_KEY });
      const uncompressed = Buffer.from(pubResp['publicKey'] as string, 'base64');
      expect(uncompressed.length).toBe(65);
      // Recompress to compare against the documented 33-byte compressed form.
      const compressed = secp256k1.ProjectivePoint
        .fromHex(uncompressed)
        .toRawBytes(true);
      expect(Buffer.from(compressed).toString('hex')).toBe(
        DD_ECIES_TEST_PUBLIC_KEY_COMPRESSED_HEX,
      );

      const envelope = hex(DD_ECIES_TEST_BASIC_ENVELOPE_HEX);
      const r = await client.send({
        cmd: EBP1_COMMANDS.ENCLAVE_DECRYPT,
        data: envelope.toString('base64'),
      });
      expect(r['error']).toBeUndefined();
      const plaintext = Buffer.from(r['plaintext'] as string, 'base64');
      expect(plaintext.toString('hex')).toBe(DD_ECIES_TEST_PLAINTEXT_HEX);
    } finally {
      await tearDown();
    }
  });

  it('returns "Encrypted data too short" for a too-short envelope', async () => {
    await setUp();
    try {
      const r = await client.send({
        cmd: EBP1_COMMANDS.ENCLAVE_DECRYPT,
        data: Buffer.alloc(40, 0x00).toString('base64'),
      });
      expect(r['error']).toBe(EBP1_ERRORS.ENCRYPTED_DATA_TOO_SHORT);
    } finally {
      await tearDown();
    }
  });

  it('returns "Decryption failed" when the envelope was addressed to a different key', async () => {
    // Bridge generates a fresh key — the DD-ECIES envelope is addressed to
    // a *different* key, so AES-GCM tag verification will fail.
    await setUp();
    try {
      const envelope = hex(DD_ECIES_TEST_BASIC_ENVELOPE_HEX);
      const r = await client.send({
        cmd: EBP1_COMMANDS.ENCLAVE_DECRYPT,
        data: envelope.toString('base64'),
      });
      expect(r['error']).toBe(EBP1_ERRORS.DECRYPTION_FAILED);
    } finally {
      await tearDown();
    }
  });

  it('returns "Invalid ephemeral public key format" when the prefix byte is not 0x02 or 0x03', async () => {
    // RFC v3 §15 (Compatibility posture): BrightNexus opts out of the
    // DD-ECIES §5.3 65/64-byte tolerance on all decode paths. Only 33-byte
    // compressed (prefix 0x02 or 0x03) is accepted. This test exercises
    // both a clearly-bogus prefix (0x05) and the formerly-tolerated
    // uncompressed prefix (0x04) to lock in the new strict behavior.
    await setUp();
    try {
      // 0x05 — never legal in any DD-ECIES decoder.
      const bogus = Buffer.concat([
        Buffer.from([
          ECIES_VERSION_BYTE,
          ECIES_CIPHER_SUITE_BYTE,
          ECIES_ENCRYPTION_TYPE.BASIC,
        ]),
        Buffer.from([0x05]),
        Buffer.alloc(32, 0x00),
        Buffer.alloc(ECIES_IV_SIZE, 0x00),
        Buffer.alloc(ECIES_AUTH_TAG_SIZE, 0x00),
        Buffer.alloc(8, 0x00),
      ]);
      const r1 = await client.send({
        cmd: EBP1_COMMANDS.ENCLAVE_DECRYPT,
        data: bogus.toString('base64'),
      });
      expect(r1['error']).toBe(EBP1_ERRORS.INVALID_EPHEMERAL_PUBLIC_KEY_FORMAT);

      // 0x04-prefixed 65-byte uncompressed — used to be accepted (DD-ECIES
      // §5.3). v3 BrightNexus rejects it.
      const uncompressed = Buffer.concat([
        Buffer.from([
          ECIES_VERSION_BYTE,
          ECIES_CIPHER_SUITE_BYTE,
          ECIES_ENCRYPTION_TYPE.BASIC,
        ]),
        Buffer.from([0x04]),
        Buffer.alloc(64, 0x00), // x || y
        Buffer.alloc(ECIES_IV_SIZE, 0x00),
        Buffer.alloc(ECIES_AUTH_TAG_SIZE, 0x00),
        Buffer.alloc(8, 0x00),
      ]);
      const r2 = await client.send({
        cmd: EBP1_COMMANDS.ENCLAVE_DECRYPT,
        data: uncompressed.toString('base64'),
      });
      expect(r2['error']).toBe(EBP1_ERRORS.INVALID_EPHEMERAL_PUBLIC_KEY_FORMAT);
    } finally {
      await tearDown();
    }
  });
});

// ─── ENCLAVE_SIGN — verifiable against the SEP stand-in's public key ───

describe('mock-brightnexus ENCLAVE_SIGN', () => {
  beforeEach(async () => { await setUp(); });
  afterEach(async () => { await tearDown(); });

  it('signature verifies against the SEP public key (DER over P-256, SHA-256)', async () => {
    const message = Buffer.from('hello, mock SEP', 'utf8');
    const signResp = await client.send({
      cmd: EBP1_COMMANDS.ENCLAVE_SIGN,
      data: message.toString('base64'),
    });
    const sig = Buffer.from(signResp['signature'] as string, 'base64');
    const pubResp = await client.send({ cmd: EBP1_COMMANDS.GET_ENCLAVE_PUBLIC_KEY });
    const pubUncompressed = Buffer.from(pubResp['publicKey'] as string, 'base64');

    // Convert the 65-byte uncompressed point into a Node KeyObject for verify.
    const x = pubUncompressed.subarray(1, 33);
    const y = pubUncompressed.subarray(33, 65);
    const jwk = {
      kty: 'EC' as const,
      crv: 'P-256' as const,
      x: x.toString('base64url'),
      y: y.toString('base64url'),
    };
    const pubKeyObj = createPublicKey({ key: jwk, format: 'jwk' });
    const verifier = createVerify('SHA256');
    verifier.update(message);
    expect(verifier.verify({ key: pubKeyObj, dsaEncoding: 'der' }, sig)).toBe(true);
  });

  it('rejects missing data with the spec error', async () => {
    const r = await client.send({ cmd: EBP1_COMMANDS.ENCLAVE_SIGN });
    expect(r['error']).toBe(EBP1_ERRORS.MISSING_OR_INVALID_DATA_TO_SIGN);
  });
});

// ─── LINK_REGISTER — Phase 2 happy path + rejection paths ───────────────

/** Helpers that synthesize a valid `LINK_REGISTER` request for tests. */
async function buildRegisterRequest(
  bridgePub: Buffer,
  overrides: { issuedAtBd?: number; protocolVersion?: number; ttlSeconds?: number; clientNonce?: Buffer; clientShare?: Buffer; clientPriv?: Buffer; clientPub?: Buffer } = {},
): Promise<{
  request: Record<string, unknown>;
  clientPriv: Buffer;
  clientPub: Buffer;
  clientShare: Buffer;
  clientNonce: Buffer;
  issuedAtBd: number;
}> {
  const { randomBytes } = await import('node:crypto');
  const clientNonce = overrides.clientNonce ?? Buffer.from(randomBytes(LINK_CLIENT_NONCE_LENGTH));
  const clientShare = overrides.clientShare ?? Buffer.from(randomBytes(LINK_SHARE_LENGTH));
  const clientPriv = overrides.clientPriv ?? Buffer.from(randomBytes(32));
  const clientPub =
    overrides.clientPub ??
    Buffer.from(secp256k1.getPublicKey(clientPriv, false));

  const issuedAtBd = overrides.issuedAtBd ?? 9637.5;
  const ttlSeconds = overrides.ttlSeconds ?? 3600;

  const plaintext = Buffer.from(
    JSON.stringify({
      v: LINK_PROTOCOL_VERSION,
      clientPub: clientPub.toString('base64'),
      clientShare: clientShare.toString('base64'),
      issuedAtBd,
      ttlSeconds,
      agent: { name: 'test-bsh', version: '0.0.1', platform: 'node-test' },
    }),
  );

  const envelope = encryptToBridge(plaintext, bridgePub);
  return {
    request: {
      cmd: LINK_COMMANDS.REGISTER,
      protocolVersion: overrides.protocolVersion ?? LINK_PROTOCOL_VERSION,
      clientNonce: clientNonce.toString('base64'),
      envelope: envelope.toString('base64'),
    },
    clientPriv,
    clientPub,
    clientShare,
    clientNonce,
    issuedAtBd,
  };
}

/** Build a DD-ECIES Basic-mode envelope (test-side encryptor). */
function encryptToBridge(plaintext: Buffer, bridgePubUncompressed: Buffer): Buffer {
  const ephPriv = (() => {
    const { randomBytes } = require('node:crypto');
    return Buffer.from(randomBytes(32));
  })();
  const ephPubCompressed = Buffer.from(secp256k1.getPublicKey(ephPriv, true));
  const shared33 = secp256k1.getSharedSecret(ephPriv, bridgePubUncompressed, true);
  const x32 = shared33.subarray(1);
  const aesKey = Buffer.from(
    hkdf(sha256, x32, new Uint8Array(0), ECIES_HKDF_INFO, ECIES_HKDF_OUTPUT_LENGTH),
  );
  const iv = (() => {
    const { randomBytes } = require('node:crypto');
    return Buffer.from(randomBytes(ECIES_IV_SIZE));
  })();
  const aad = Buffer.concat([
    Buffer.from([ECIES_VERSION_BYTE, ECIES_CIPHER_SUITE_BYTE, ECIES_ENCRYPTION_TYPE.BASIC]),
    ephPubCompressed,
  ]);
  const cipher = createCipheriv('aes-256-gcm', aesKey, iv, { authTagLength: ECIES_AUTH_TAG_SIZE });
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([
    Buffer.from([ECIES_VERSION_BYTE, ECIES_CIPHER_SUITE_BYTE, ECIES_ENCRYPTION_TYPE.BASIC]),
    ephPubCompressed,
    iv,
    tag,
    ct,
  ]);
}

/** Decrypt the bridge's responseEnvelope to recover bridgeShare. */
function decryptFromBridge(envelope: Buffer, clientPriv: Buffer): Buffer {
  // Parse Basic-mode envelope.
  expect(envelope[0]).toBe(ECIES_VERSION_BYTE);
  expect(envelope[1]).toBe(ECIES_CIPHER_SUITE_BYTE);
  expect(envelope[2]).toBe(ECIES_ENCRYPTION_TYPE.BASIC);
  const ephPub = envelope.subarray(3, 36); // 33 bytes compressed
  const iv = envelope.subarray(36, 48);
  const tag = envelope.subarray(48, 64);
  const ct = envelope.subarray(64);

  const shared33 = secp256k1.getSharedSecret(clientPriv, ephPub, true);
  const x32 = shared33.subarray(1);
  const aesKey = Buffer.from(
    hkdf(sha256, x32, new Uint8Array(0), ECIES_HKDF_INFO, ECIES_HKDF_OUTPUT_LENGTH),
  );
  const aad = Buffer.concat([
    Buffer.from([envelope[0], envelope[1], envelope[2]]),
    ephPub,
  ]);
  const { createDecipheriv } = require('node:crypto');
  const decipher = createDecipheriv('aes-256-gcm', aesKey, iv, { authTagLength: ECIES_AUTH_TAG_SIZE });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

describe('mock-brightnexus LINK_REGISTER (RFC §4.5)', () => {
  beforeEach(async () => { await setUp(); });
  afterEach(async () => { await tearDown(); });

  it('completes a happy-path registration and returns a valid response shape', async () => {
    // 1. Get the bridge's persistent secp256k1 public key.
    const pubResp = await client.send({ cmd: EBP1_COMMANDS.GET_PUBLIC_KEY });
    const bridgePub = Buffer.from(pubResp['publicKey'] as string, 'base64');

    // 2. Build a valid registration.
    const built = await buildRegisterRequest(bridgePub);
    const r = await client.send(built.request);

    // 3. Response shape per RFC §4.5.3.
    expect(r['error']).toBeUndefined();
    expect(r['ok']).toBe(true);
    expect(typeof r['sessionId']).toBe('string');
    expect(typeof r['bridgeIssuedAtUnix']).toBe('number');
    expect(typeof r['ttlSeconds']).toBe('number');
    expect(typeof r['responseEnvelope']).toBe('string');
    expect(typeof r['transcriptSig']).toBe('string');

    const sessionId = Buffer.from(r['sessionId'] as string, 'base64');
    expect(sessionId.length).toBe(LINK_SESSION_ID_LENGTH);

    // 4. Decrypt the responseEnvelope to recover bridgeShare.
    const responseEnvelope = Buffer.from(r['responseEnvelope'] as string, 'base64');
    const bridgeShare = decryptFromBridge(responseEnvelope, built.clientPriv);
    expect(bridgeShare.length).toBe(LINK_SHARE_LENGTH);

    // 5. Derive K_session client-side and verify the bridge's session
    //    matches by checking the audit log.
    const { ikm, salt, info, outputByteCount } = buildSessionKeyHkdfInputs({
      clientNonce: built.clientNonce,
      sessionId,
      clientShare: built.clientShare,
      bridgeShare,
    });
    const clientKSession = Buffer.from(hkdf(sha256, ikm, salt, info, outputByteCount));
    expect(clientKSession.length).toBe(LINK_SESSION_KEY_LENGTH);

    // The audit log should contain a session_init event for this session id.
    const audit = mock.state.auditLog;
    const session = audit.find(
      (e) => e.kind === 'session_init' && e.sessionIdHex === sessionId.toString('hex'),
    );
    expect(session).toBeDefined();
  });

  it('verifies the transcript signature against the SEP public key', async () => {
    const pubResp = await client.send({ cmd: EBP1_COMMANDS.GET_PUBLIC_KEY });
    const bridgePub = Buffer.from(pubResp['publicKey'] as string, 'base64');
    const sepResp = await client.send({ cmd: EBP1_COMMANDS.GET_ENCLAVE_PUBLIC_KEY });
    const sepPub = Buffer.from(sepResp['publicKey'] as string, 'base64');

    const built = await buildRegisterRequest(bridgePub);
    const r = await client.send(built.request);
    expect(r['ok']).toBe(true);

    const sessionId = Buffer.from(r['sessionId'] as string, 'base64');
    const responseEnvelope = Buffer.from(r['responseEnvelope'] as string, 'base64');
    const bridgeShare = decryptFromBridge(responseEnvelope, built.clientPriv);
    const transcriptSig = Buffer.from(r['transcriptSig'] as string, 'base64');

    // Reconstruct the canonical transcript and verify the signature
    // against the SEP public key.
    const transcript = buildTranscript({
      clientNonce: built.clientNonce,
      clientPub: built.clientPub,
      clientShare: built.clientShare,
      sessionId,
      bridgeShare,
      issuedAtBd: built.issuedAtBd,
      bridgeIssuedAtUnix: r['bridgeIssuedAtUnix'] as number,
      ttlSeconds: r['ttlSeconds'] as number,
    });

    // Verify with the bridge's SEP public key.
    const x = sepPub.subarray(1, 33);
    const y = sepPub.subarray(33, 65);
    const jwk = {
      kty: 'EC' as const,
      crv: 'P-256' as const,
      x: x.toString('base64url'),
      y: y.toString('base64url'),
    };
    const sepPubKey = createPublicKey({ key: jwk, format: 'jwk' });
    const verifier = createVerify('SHA256');
    verifier.update(transcript);
    expect(verifier.verify({ key: sepPubKey, dsaEncoding: 'der' }, transcriptSig)).toBe(true);
  });

  it('rejects a wrong protocol version', async () => {
    const pubResp = await client.send({ cmd: EBP1_COMMANDS.GET_PUBLIC_KEY });
    const bridgePub = Buffer.from(pubResp['publicKey'] as string, 'base64');
    const built = await buildRegisterRequest(bridgePub, { protocolVersion: 2 });
    const r = await client.send(built.request);
    expect(r['error']).toBe('Unsupported SDI protocol version');
  });

  it('rejects a missing clientNonce', async () => {
    const pubResp = await client.send({ cmd: EBP1_COMMANDS.GET_PUBLIC_KEY });
    const bridgePub = Buffer.from(pubResp['publicKey'] as string, 'base64');
    const built = await buildRegisterRequest(bridgePub);
    delete (built.request as Record<string, unknown>)['clientNonce'];
    const r = await client.send(built.request);
    expect(r['error']).toBe('Missing clientNonce');
  });

  it('rejects an undecryptable envelope', async () => {
    const r = await client.send({
      cmd: LINK_COMMANDS.REGISTER,
      protocolVersion: LINK_PROTOCOL_VERSION,
      clientNonce: Buffer.alloc(LINK_CLIENT_NONCE_LENGTH).toString('base64'),
      envelope: Buffer.alloc(100, 0x00).toString('base64'),
    });
    expect(r['error']).toBe('Decryption failed');
  });

  it('rejects an issuedAtBd that is more than 60 seconds in the future', async () => {
    // Fix the bridge clock at 2025-01-01T00:00:00Z and request a registration
    // from "tomorrow". Should be rejected.
    await tearDown();
    await setUp({ nowUnix: () => 1735689600 });
    try {
      const pubResp2 = await client.send({ cmd: EBP1_COMMANDS.GET_PUBLIC_KEY });
      const bridgePub2 = Buffer.from(pubResp2['publicKey'] as string, 'base64');
      // Pick an issuedAtBd that resolves to ~24h ahead of the bridge clock.
      // BrightDate scalar = unix_seconds / 86400 (the spec's `issuedAtBd *
      // 86400` gives back unix seconds), so unix+86400 / 86400 = "tomorrow".
      const built = await buildRegisterRequest(bridgePub2, {
        issuedAtBd: (1735689600 + 86400) / 86400,
      });
      const r = await client.send(built.request);
      expect(r['error']).toBe('Stale registration');
    } finally {
      // Re-setup for the outer afterEach to tear down.
      await setUp();
    }
  });

  it('caps requested ttlSeconds at LINK_MAX_TTL_SECONDS', async () => {
    const pubResp = await client.send({ cmd: EBP1_COMMANDS.GET_PUBLIC_KEY });
    const bridgePub = Buffer.from(pubResp['publicKey'] as string, 'base64');
    const built = await buildRegisterRequest(bridgePub, {
      ttlSeconds: LINK_MAX_TTL_SECONDS * 10,
    });
    const r = await client.send(built.request);
    expect(r['ok']).toBe(true);
    expect(r['ttlSeconds']).toBe(LINK_MAX_TTL_SECONDS);
  });
});

// ─── LINK_PUSH subscription (RFC §10) ───────────────────────────────────
//
// The §10 push surface takes `subscribe: ["event-name", ...]` and emits
// AAD-sealed event frames whenever the bridge engine reports an event of
// that kind. This test pair exercises the wire-shape — the
// against-real-client and against-real-bsh suites cover end-to-end
// AEAD verification.

describe('mock-brightnexus LINK_PUSH (RFC §10)', () => {
  beforeEach(async () => { await setUp(); });
  afterEach(async () => { await tearDown(); });

  it('subscribe → receive zone-transition frame on engine zone change', async () => {
    // 1. Register first.
    const pubResp = await client.send({ cmd: EBP1_COMMANDS.GET_PUBLIC_KEY });
    const bridgePub = Buffer.from(pubResp['publicKey'] as string, 'base64');
    const built = await buildRegisterRequest(bridgePub);
    const reg = await client.send(built.request);
    expect(reg['ok']).toBe(true);

    // 2. Set up a push handler on the test client BEFORE subscribing.
    const received: Record<string, unknown>[] = [];
    client.pushHandler = (e) => { received.push(e); };

    // 3. Subscribe to zone-transition events.
    const sub = await client.send({
      cmd: LINK_COMMANDS.PUSH,
      subscribe: ['zone-transition'],
    });
    expect(sub['ok']).toBe(true);
    expect(sub['subscribed']).toEqual(['zone-transition']);

    // 4. Configure a zone and pin a fix inside it.
    //    (Imported via the mock-brightnexus public surface.)
    mock.state.zones.setZones([
      {
        id: 'zone-prod-office',
        displayName: 'Prod Office',
        shape: {
          type: 'circle_2d',
          center: { wgs84: { lat: 47.6062, lon: -122.3321 } },
          radius_m: 200,
        },
      },
    ]);
    // Cast the geo source to FixedGeoSource so we can pin a fix.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (mock.state.geoSource as any).setFixFromWgs84({
      lat: 47.6062,
      lon: -122.3321,
      accuracy_m: 5,
    });
    // Force the engine to evaluate; the subscriber should see one
    // zone-transition frame (null → zone-prod-office).
    mock.state.geo.forceEvaluateZone();

    // 5. Wait for the push to arrive.
    await new Promise((r) => setTimeout(r, 50));
    expect(received).toHaveLength(1);
    expect(received[0]?.['event']).toBe('zone-transition');
    expect(typeof received[0]?.['counter']).toBe('number');
    expect(received[0]?.['counter']).toBe(1);
    expect(typeof received[0]?.['iv']).toBe('string');
    expect(typeof received[0]?.['ciphertext']).toBe('string');
    expect(typeof received[0]?.['authTag']).toBe('string');
  });

  it('rejects subscribe before LINK_REGISTER on the same connection', async () => {
    const r = await client.send({
      cmd: LINK_COMMANDS.PUSH,
      subscribe: ['zone-transition'],
    });
    expect(r['error']).toBe('push: session not registered');
  });

  it('rejects subscribe with no recognised event types', async () => {
    // Establish a session first so we don't hit the session-not-registered
    // error path.
    const pubResp = await client.send({ cmd: EBP1_COMMANDS.GET_PUBLIC_KEY });
    const bridgePub = Buffer.from(pubResp['publicKey'] as string, 'base64');
    const built = await buildRegisterRequest(bridgePub);
    await client.send(built.request);

    const r = await client.send({
      cmd: LINK_COMMANDS.PUSH,
      subscribe: ['totally-made-up-event'],
    });
    expect(r['error']).toBe('push: unknown event types');
  });
});

// ─── BrightLink v1.1 — geo command surface (implemented in Wave 2) ──────

describe('mock-brightnexus LINK_GEO_* require a registered session', () => {
  beforeEach(async () => { await setUp(); });
  afterEach(async () => { await tearDown(); });

  // The geo commands return `geo: session not registered` when no
  // LINK_REGISTER session is bound to the connection. End-to-end geo
  // tests that exercise the gating + prompt flow live in `geo-engine.test.ts`.
  for (const cmd of [
    LINK_COMMANDS.GEO_STATUS,
    LINK_COMMANDS.GEO_PROXIMITY,
    LINK_COMMANDS.GEO_ZONE,
    LINK_COMMANDS.GEO_GET,
    LINK_COMMANDS.GEO_REFRESH,
  ]) {
    it(`${cmd} without a session returns "geo: session not registered"`, async () => {
      const r = await client.send({ cmd });
      expect(r['error']).toBe('geo: session not registered');
    });
  }

  it('LINK_AUDIT_EMIT remains reserved (RFC §11)', async () => {
    const r = await client.send({ cmd: LINK_COMMANDS.AUDIT_EMIT });
    expect(r['error']).toBe(
      `${LINK_COMMANDS.AUDIT_EMIT}${LINK_ERROR_NOT_IMPLEMENTED_SUFFIX}`,
    );
  });
});
