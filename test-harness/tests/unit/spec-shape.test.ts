/**
 * Spec-internal-consistency tests.
 *
 * These verify that the constants in `src/spec/` agree with each other and
 * agree with the citations they claim to come from. They do not exercise any
 * mock or real implementation — that's what the other test files are for.
 *
 * If a test in this file fails, the spec module has a bug. If a test in this
 * file passes but `mock-brightnexus` or the real bridge fails interop, the
 * bug is in that implementation, not in the spec.
 */

import { describe, it, expect } from 'vitest';

import {
  // EBP/1
  EBP1_COMMANDS,
  EBP1_KEY_IDS,
  EBP1_SERVICE_NAME,
  EBP1_SOCKET_DISCOVERY_ORDER,
  EBP1_MESSAGE_TERMINATOR,
  // ECIES
  ECIES_BASIC_FIXED_OVERHEAD,
  ECIES_WITH_LENGTH_FIXED_OVERHEAD,
  ECIES_DATA_LENGTH_SIZE,
  ECIES_HKDF_INFO,
  ECIES_HKDF_SALT,
  ECIES_HKDF_OUTPUT_LENGTH,
  ECIES_VERSION_BYTE,
  ECIES_CIPHER_SUITE_BYTE,
  ECIES_ENCRYPTION_TYPE,
  ECIES_PUBLIC_KEY_LENGTH,
  ECIES_RAW_PUBLIC_KEY_LENGTH,
  ECIES_PUBLIC_KEY_MAGIC,
  ECIES_UNCOMPRESSED_PUBLIC_KEY_LENGTH,
  ECIES_BARE_PUBLIC_KEY_LENGTH,
  ECIES_IV_SIZE,
  ECIES_AUTH_TAG_SIZE,
  ECIES_SYMMETRIC_KEY_BITS,
  ECIES_SYMMETRIC_KEY_SIZE,
  // BrightLink
  LINK_PROTOCOL_VERSION,
  LINK_SESSION_KEY_HKDF_INFO,
  LINK_SESSION_KEY_LENGTH,
  LINK_MAX_TTL_SECONDS,
  LINK_CLIENT_NONCE_LENGTH,
  LINK_SHARE_LENGTH,
  LINK_SESSION_ID_LENGTH,
  LINK_TRANSCRIPT_HEADER,
  LINK_TRANSCRIPT_TOTAL_LENGTH,
  LINK_DIR_TAG,
  LINK_COUNTER_REPLAY_WINDOW,
  buildSessionKeyHkdfInputs,
  buildTranscript,
  buildDeliverAad,
} from '../../src/spec/index.js';

describe('EBP/1 spec internal consistency', () => {
  it('all command names are non-empty UPPER_SNAKE_CASE', () => {
    for (const [key, value] of Object.entries(EBP1_COMMANDS)) {
      expect(value, `command name for ${key}`).toMatch(/^[A-Z][A-Z0-9_]*$/);
    }
  });

  it('VERSION and INFO are documented as aliases', () => {
    // EBP/1 §4.2 states INFO is an alias for VERSION. We don't enforce that
    // they're equal-valued (they're distinct strings on the wire), only that
    // both are present.
    expect(EBP1_COMMANDS.VERSION).toBe('VERSION');
    expect(EBP1_COMMANDS.INFO).toBe('INFO');
  });

  it('reserved key ids are exactly two', () => {
    expect(Object.keys(EBP1_KEY_IDS)).toHaveLength(2);
    expect(EBP1_KEY_IDS.ECIES_SECP256K1).toBe('ecies-secp256k1');
    expect(EBP1_KEY_IDS.SECURE_ENCLAVE_P256).toBe('secure-enclave-p256');
  });

  it('service name is the legacy identifier (preserved for backward compat)', () => {
    expect(EBP1_SERVICE_NAME).toBe('enclave-bridge');
  });

  it('socket discovery order has the canonical path first, legacy second', () => {
    const home = '/home/test';
    const paths = EBP1_SOCKET_DISCOVERY_ORDER.map((fn) => fn(home));
    expect(paths[0]).toBe('/home/test/.brightchain/brightnexus/brightnexus.sock');
    expect(paths[1]).toBe('/home/test/.enclave/enclave-bridge.sock');
  });

  it('framing byte is the JSON closing brace', () => {
    expect(EBP1_MESSAGE_TERMINATOR).toBe(0x7d);
    expect(String.fromCharCode(EBP1_MESSAGE_TERMINATOR)).toBe('}');
  });
});

describe('DD-ECIES spec internal consistency', () => {
  it('basic-mode fixed overhead = 1+1+1+33+12+16 = 64 bytes', () => {
    const sum =
      1 + // version
      1 + // cipherSuite
      1 + // type
      ECIES_PUBLIC_KEY_LENGTH +
      ECIES_IV_SIZE +
      ECIES_AUTH_TAG_SIZE;
    expect(sum).toBe(64);
    expect(ECIES_BASIC_FIXED_OVERHEAD).toBe(sum);
  });

  it('with-length-mode overhead = basic + 8-byte length field = 72', () => {
    expect(ECIES_WITH_LENGTH_FIXED_OVERHEAD).toBe(
      ECIES_BASIC_FIXED_OVERHEAD + ECIES_DATA_LENGTH_SIZE,
    );
    expect(ECIES_WITH_LENGTH_FIXED_OVERHEAD).toBe(72);
  });

  it('public key length relations hold', () => {
    expect(ECIES_PUBLIC_KEY_LENGTH).toBe(ECIES_RAW_PUBLIC_KEY_LENGTH + 1);
    expect(ECIES_UNCOMPRESSED_PUBLIC_KEY_LENGTH).toBe(
      ECIES_BARE_PUBLIC_KEY_LENGTH + 1,
    );
    expect(ECIES_PUBLIC_KEY_LENGTH).toBe(33);
    expect(ECIES_UNCOMPRESSED_PUBLIC_KEY_LENGTH).toBe(65);
    expect(ECIES_BARE_PUBLIC_KEY_LENGTH).toBe(64);
  });

  it('symmetric key size relation: KEY_SIZE = KEY_BITS / 8', () => {
    expect(ECIES_SYMMETRIC_KEY_SIZE).toBe(ECIES_SYMMETRIC_KEY_BITS / 8);
    expect(ECIES_SYMMETRIC_KEY_SIZE).toBe(32);
  });

  it('IV is 12 bytes per DD-ECIES §9.2 (NOT the deprecated 16-byte form)', () => {
    expect(ECIES_IV_SIZE).toBe(12);
  });

  it('HKDF info is "ecies-v2-key-derivation" (23 bytes UTF-8)', () => {
    expect(ECIES_HKDF_INFO).toBe('ecies-v2-key-derivation');
    expect(Buffer.byteLength(ECIES_HKDF_INFO, 'utf8')).toBe(23);
  });

  it('HKDF salt is empty', () => {
    expect(ECIES_HKDF_SALT.length).toBe(0);
  });

  it('HKDF output length = symmetric key size = 32', () => {
    expect(ECIES_HKDF_OUTPUT_LENGTH).toBe(ECIES_SYMMETRIC_KEY_SIZE);
  });

  it('version, cipher suite, and encryption type bytes match DD-ECIES §17', () => {
    expect(ECIES_VERSION_BYTE).toBe(0x01);
    expect(ECIES_CIPHER_SUITE_BYTE).toBe(0x01);
    expect(ECIES_ENCRYPTION_TYPE.BASIC).toBe(0x21);
    expect(ECIES_ENCRYPTION_TYPE.WITH_LENGTH).toBe(0x42);
    expect(ECIES_ENCRYPTION_TYPE.MULTIPLE).toBe(0x63);
  });

  it('default compressed-key prefix is 0x02 (even y)', () => {
    expect(ECIES_PUBLIC_KEY_MAGIC).toBe(0x02);
  });
});

describe('BrightLink v1 spec internal consistency', () => {
  it('protocol version is 1', () => {
    expect(LINK_PROTOCOL_VERSION).toBe(1);
  });

  it('session-key HKDF info is "brightlink-session-key-v1"', () => {
    expect(LINK_SESSION_KEY_HKDF_INFO).toBe('brightlink-session-key-v1');
    // 25 UTF-8 bytes.
    expect(Buffer.byteLength(LINK_SESSION_KEY_HKDF_INFO, 'utf8')).toBe(25);
  });

  it('session key length matches AES-256-GCM key size', () => {
    expect(LINK_SESSION_KEY_LENGTH).toBe(ECIES_SYMMETRIC_KEY_SIZE);
  });

  it('max TTL is 8 hours = 28800 seconds', () => {
    expect(LINK_MAX_TTL_SECONDS).toBe(8 * 3600);
    expect(LINK_MAX_TTL_SECONDS).toBe(28800);
  });

  it('field lengths: clientNonce=16, share=32, sessionId=16', () => {
    expect(LINK_CLIENT_NONCE_LENGTH).toBe(16);
    expect(LINK_SHARE_LENGTH).toBe(32);
    expect(LINK_SESSION_ID_LENGTH).toBe(16);
  });

  it('transcript header is 25 bytes ending in NUL', () => {
    expect(LINK_TRANSCRIPT_HEADER.length).toBe(25);
    expect(LINK_TRANSCRIPT_HEADER[LINK_TRANSCRIPT_HEADER.length - 1]).toBe(0x00);
    expect(LINK_TRANSCRIPT_HEADER.subarray(0, 24).toString('utf8')).toBe(
      'BrightLink v1 transcript',
    );
  });

  it('canonical transcript total length = 238 bytes', () => {
    // Recompute from the field layout described in RFC §4.5.3 to catch
    // arithmetic drift in the constant.
    const expected =
      25 + // header (was 21 in BrightLink v1)
      4 + 16 + // clientNonce
      4 + 65 + // clientPub (uncompressed)
      4 + 32 + // clientShare
      4 + 16 + // sessionId
      4 + 32 + // bridgeShare
      4 + 8 + // issuedAtBd → u64_be
      4 + 8 + // bridgeIssuedAtUnix → u64_be
      4 + 4; // ttlSeconds → u32_be
    expect(expected).toBe(238);
    expect(LINK_TRANSCRIPT_TOTAL_LENGTH).toBe(238);
  });

  it('dir_tag values: 0x01 shell→agent, 0x02 agent→shell', () => {
    expect(LINK_DIR_TAG.SHELL_TO_AGENT).toBe(0x01);
    expect(LINK_DIR_TAG.AGENT_TO_SHELL).toBe(0x02);
  });

  it('counter replay window is 1000', () => {
    expect(LINK_COUNTER_REPLAY_WINDOW).toBe(1000);
  });
});

describe('BrightLink derivation helpers', () => {
  const fixedNonce = Buffer.alloc(16, 0xab);
  const fixedSessionId = Buffer.alloc(16, 0xcd);
  const fixedClientShare = Buffer.alloc(32, 0xef);
  const fixedBridgeShare = Buffer.alloc(32, 0x12);

  it('buildSessionKeyHkdfInputs: shapes are correct', () => {
    const out = buildSessionKeyHkdfInputs({
      clientNonce: fixedNonce,
      sessionId: fixedSessionId,
      clientShare: fixedClientShare,
      bridgeShare: fixedBridgeShare,
    });
    expect(out.ikm.length).toBe(64);
    expect(out.salt.length).toBe(32);
    expect(out.info.toString('utf8')).toBe('brightlink-session-key-v1');
    expect(out.outputByteCount).toBe(32);

    // IKM = clientShare || bridgeShare (NOT bridgeShare || clientShare).
    expect(Buffer.from(out.ikm).subarray(0, 32).equals(fixedClientShare)).toBe(true);
    expect(Buffer.from(out.ikm).subarray(32, 64).equals(fixedBridgeShare)).toBe(true);

    // salt = clientNonce || sessionId.
    expect(Buffer.from(out.salt).subarray(0, 16).equals(fixedNonce)).toBe(true);
    expect(Buffer.from(out.salt).subarray(16, 32).equals(fixedSessionId)).toBe(true);
  });

  it('buildSessionKeyHkdfInputs: rejects mis-sized inputs', () => {
    expect(() =>
      buildSessionKeyHkdfInputs({
        clientNonce: Buffer.alloc(15),
        sessionId: fixedSessionId,
        clientShare: fixedClientShare,
        bridgeShare: fixedBridgeShare,
      }),
    ).toThrow(/clientNonce must be 16 bytes/);
    expect(() =>
      buildSessionKeyHkdfInputs({
        clientNonce: fixedNonce,
        sessionId: fixedSessionId,
        clientShare: Buffer.alloc(31),
        bridgeShare: fixedBridgeShare,
      }),
    ).toThrow(/clientShare must be 32 bytes/);
  });

  it('buildTranscript: produces exactly LINK_TRANSCRIPT_TOTAL_LENGTH bytes for canonical inputs', () => {
    const t = buildTranscript({
      clientNonce: fixedNonce,
      clientPub: Buffer.alloc(65, 0x04), // 65-byte uncompressed (placeholder)
      clientShare: fixedClientShare,
      sessionId: fixedSessionId,
      bridgeShare: fixedBridgeShare,
      issuedAtBd: 9637.5,
      bridgeIssuedAtUnix: 1_747_915_200,
      ttlSeconds: 3600,
    });
    expect(t.length).toBe(LINK_TRANSCRIPT_TOTAL_LENGTH);
    // First N bytes are the literal header.
    expect(t.subarray(0, LINK_TRANSCRIPT_HEADER.length).equals(LINK_TRANSCRIPT_HEADER)).toBe(true);
  });

  it('buildTranscript: rejects mis-sized inputs', () => {
    expect(() =>
      buildTranscript({
        clientNonce: Buffer.alloc(15),
        clientPub: Buffer.alloc(65),
        clientShare: fixedClientShare,
        sessionId: fixedSessionId,
        bridgeShare: fixedBridgeShare,
        issuedAtBd: 9637.5,
        bridgeIssuedAtUnix: 0,
        ttlSeconds: 0,
      }),
    ).toThrow(/clientNonce must be 16 bytes/);

    expect(() =>
      buildTranscript({
        clientNonce: fixedNonce,
        clientPub: Buffer.alloc(33), // wrong: should be 65
        clientShare: fixedClientShare,
        sessionId: fixedSessionId,
        bridgeShare: fixedBridgeShare,
        issuedAtBd: 9637.5,
        bridgeIssuedAtUnix: 0,
        ttlSeconds: 0,
      }),
    ).toThrow(/clientPub must be 65 bytes/);
  });

  it('buildDeliverAad: prefixed dir_tag is 1 byte with LE32(1) prefix', () => {
    const aad = buildDeliverAad({
      dirTag: LINK_DIR_TAG.SHELL_TO_AGENT,
      counter: 0n,
      type: '',
      contextBytes: Buffer.alloc(0),
    });
    // Layout: LE32(1) || 0x01 || LE32(8) || 8 zero bytes ||
    //         LE32(0) || (empty type) || LE32(0) || (empty ctx)
    // Total = 4 + 1 + 4 + 8 + 4 + 4 = 25 bytes.
    expect(aad.length).toBe(25);
    expect(aad.readUInt32LE(0)).toBe(1);
    expect(aad[4]).toBe(0x01);
    expect(aad.readUInt32LE(5)).toBe(8);
    expect(aad.readBigUInt64BE(9)).toBe(0n);
    expect(aad.readUInt32LE(17)).toBe(0); // type length
    expect(aad.readUInt32LE(21)).toBe(0); // ctx length
  });

  it('buildDeliverAad: counter is big-endian uint64', () => {
    const aad = buildDeliverAad({
      dirTag: LINK_DIR_TAG.AGENT_TO_SHELL,
      counter: 0x0102_0304_0506_0708n,
      type: 'ephemeral-auth',
      contextBytes: Buffer.from('http://localhost', 'utf8'),
    });
    // dir_tag is 0x02 in this case
    expect(aad[4]).toBe(0x02);
    // Counter starts at offset 9 (after LE32(1)+dirTag+LE32(8))
    expect(aad.readBigUInt64BE(9)).toBe(0x0102_0304_0506_0708n);
  });

  it('buildDeliverAad: rejects bad dir_tag', () => {
    expect(() =>
      buildDeliverAad({
        // @ts-expect-error – exercising runtime validation
        dirTag: 0x03,
        counter: 0n,
        type: '',
        contextBytes: Buffer.alloc(0),
      }),
    ).toThrow(/dirTag must be 0x01 or 0x02/);
  });

  it('buildDeliverAad: rejects out-of-range counter', () => {
    expect(() =>
      buildDeliverAad({
        dirTag: LINK_DIR_TAG.SHELL_TO_AGENT,
        counter: -1n,
        type: '',
        contextBytes: Buffer.alloc(0),
      }),
    ).toThrow(/counter out of u64 range/);
  });
});
