/**
 * DD-ECIES known-answer tests.
 *
 * These re-derive every byte in the DD-ECIES §18 vectors using only standard
 * primitives (HKDF-SHA256 from @noble/hashes, Node's `crypto.createCipheriv`
 * for AES-256-GCM, secp256k1 from @noble/curves) and compare against the
 * hex-encoded expected values in `known-answer-vectors.ts`.
 *
 * Purpose:
 *   1. Verify that our spec-module constants (HKDF info string, IV size, AAD
 *      construction) actually produce the correct ciphertext.
 *   2. Provide a baseline that the mocks and real implementations must match.
 *      If any of these fail, the spec module is wrong.
 */

import { describe, it, expect } from 'vitest';
import { Buffer } from 'node:buffer';
import { createCipheriv, createDecipheriv } from 'node:crypto';

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { secp256k1 } from '@noble/curves/secp256k1';

import {
  ECIES_HKDF_INFO,
  ECIES_HKDF_OUTPUT_LENGTH,
  ECIES_IV_SIZE,
  ECIES_AUTH_TAG_SIZE,
} from '../../src/spec/index.js';

import {
  DD_ECIES_TEST_PRIVATE_KEY_HEX,
  DD_ECIES_TEST_PUBLIC_KEY_COMPRESSED_HEX,
  DD_ECIES_TEST_EPHEMERAL_PRIVATE_KEY_HEX,
  DD_ECIES_TEST_EPHEMERAL_PUBLIC_KEY_HEX,
  DD_ECIES_TEST_SHARED_SECRET_HEX,
  DD_ECIES_TEST_DERIVED_SYMMETRIC_KEY_HEX,
  DD_ECIES_TEST_FIXED_IV_HEX,
  DD_ECIES_TEST_PLAINTEXT_HEX,
  DD_ECIES_TEST_AAD_BASIC_HEX,
  DD_ECIES_TEST_BASIC_CIPHERTEXT_HEX,
  DD_ECIES_TEST_BASIC_AUTH_TAG_HEX,
  DD_ECIES_TEST_BASIC_ENVELOPE_HEX,
  DD_ECIES_TEST_AAD_WITH_LENGTH_HEX,
  DD_ECIES_TEST_WITH_LENGTH_AUTH_TAG_HEX,
  DD_ECIES_TEST_DATA_LENGTH_HEX,
  DD_ECIES_TEST_WITH_LENGTH_ENVELOPE_HEX,
} from '../../src/shared/known-answer-vectors.js';

const hex = (s: string) => Buffer.from(s, 'hex');

describe('DD-ECIES §6.6 — secp256k1 keypair from BIP39 test mnemonic', () => {
  it('private key derives the documented compressed public key', () => {
    // The keypair is derived externally (BIP32/BIP44); here we just verify
    // that the documented private key yields the documented public key under
    // standard secp256k1 point multiplication.
    const priv = hex(DD_ECIES_TEST_PRIVATE_KEY_HEX);
    const pubCompressed = secp256k1.getPublicKey(priv, /* compressed */ true);
    expect(Buffer.from(pubCompressed).toString('hex')).toBe(
      DD_ECIES_TEST_PUBLIC_KEY_COMPRESSED_HEX,
    );
  });
});

describe('DD-ECIES §8.4 — ECDH + HKDF-SHA256 key derivation', () => {
  it('ECDH(ephemeralPriv, recipientPub) yields the documented x-coordinate', () => {
    const ephPriv = hex(DD_ECIES_TEST_EPHEMERAL_PRIVATE_KEY_HEX);
    const recipientPub = hex(DD_ECIES_TEST_PUBLIC_KEY_COMPRESSED_HEX);
    // @noble/curves' getSharedSecret returns the compressed point (33 bytes,
    // 0x02/0x03 prefix + x). DD-ECIES strips the prefix and uses the 32-byte x.
    const shared33 = secp256k1.getSharedSecret(ephPriv, recipientPub, true);
    const x32 = shared33.subarray(1);
    expect(Buffer.from(x32).toString('hex')).toBe(DD_ECIES_TEST_SHARED_SECRET_HEX);
  });

  it('ECDH(recipientPriv, ephemeralPub) yields the same x-coordinate', () => {
    // Symmetric property: both parties see the same shared secret.
    const recipientPriv = hex(DD_ECIES_TEST_PRIVATE_KEY_HEX);
    const ephPub = hex(DD_ECIES_TEST_EPHEMERAL_PUBLIC_KEY_HEX);
    const shared33 = secp256k1.getSharedSecret(recipientPriv, ephPub, true);
    const x32 = shared33.subarray(1);
    expect(Buffer.from(x32).toString('hex')).toBe(DD_ECIES_TEST_SHARED_SECRET_HEX);
  });

  it('HKDF-SHA256 with empty salt and "ecies-v2-key-derivation" yields the documented K', () => {
    const ikm = hex(DD_ECIES_TEST_SHARED_SECRET_HEX);
    const out = hkdf(
      sha256,
      ikm,
      new Uint8Array(0), // empty salt
      ECIES_HKDF_INFO,
      ECIES_HKDF_OUTPUT_LENGTH,
    );
    expect(Buffer.from(out).toString('hex')).toBe(
      DD_ECIES_TEST_DERIVED_SYMMETRIC_KEY_HEX,
    );
  });
});

describe('DD-ECIES §18.5 — AES-256-GCM standalone known answer', () => {
  it('encrypt(K, IV, AAD, plaintext) → documented (ciphertext, authTag)', () => {
    const key = hex(DD_ECIES_TEST_DERIVED_SYMMETRIC_KEY_HEX);
    const iv = hex(DD_ECIES_TEST_FIXED_IV_HEX);
    const aad = hex(DD_ECIES_TEST_AAD_BASIC_HEX);
    const plaintext = hex(DD_ECIES_TEST_PLAINTEXT_HEX);

    expect(iv.length).toBe(ECIES_IV_SIZE);

    const cipher = createCipheriv('aes-256-gcm', key, iv, {
      authTagLength: ECIES_AUTH_TAG_SIZE,
    });
    cipher.setAAD(aad);
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    expect(ct.toString('hex')).toBe(DD_ECIES_TEST_BASIC_CIPHERTEXT_HEX);
    expect(tag.toString('hex')).toBe(DD_ECIES_TEST_BASIC_AUTH_TAG_HEX);
  });

  it('decrypt(K, IV, AAD, ciphertext, tag) → documented plaintext', () => {
    const key = hex(DD_ECIES_TEST_DERIVED_SYMMETRIC_KEY_HEX);
    const iv = hex(DD_ECIES_TEST_FIXED_IV_HEX);
    const aad = hex(DD_ECIES_TEST_AAD_BASIC_HEX);
    const ct = hex(DD_ECIES_TEST_BASIC_CIPHERTEXT_HEX);
    const tag = hex(DD_ECIES_TEST_BASIC_AUTH_TAG_HEX);

    const decipher = createDecipheriv('aes-256-gcm', key, iv, {
      authTagLength: ECIES_AUTH_TAG_SIZE,
    });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);

    expect(pt.toString('hex')).toBe(DD_ECIES_TEST_PLAINTEXT_HEX);
  });

  it('decrypt with mutated AAD fails authentication', () => {
    const key = hex(DD_ECIES_TEST_DERIVED_SYMMETRIC_KEY_HEX);
    const iv = hex(DD_ECIES_TEST_FIXED_IV_HEX);
    const aad = hex(DD_ECIES_TEST_AAD_BASIC_HEX);
    const ct = hex(DD_ECIES_TEST_BASIC_CIPHERTEXT_HEX);
    const tag = hex(DD_ECIES_TEST_BASIC_AUTH_TAG_HEX);

    // Flip the type byte — any AAD mutation must invalidate the tag.
    const mutatedAad = Buffer.from(aad);
    mutatedAad[2] = 0x42; // was 0x21

    const decipher = createDecipheriv('aes-256-gcm', key, iv, {
      authTagLength: ECIES_AUTH_TAG_SIZE,
    });
    decipher.setAAD(mutatedAad);
    decipher.setAuthTag(tag);
    expect(() => {
      Buffer.concat([decipher.update(ct), decipher.final()]);
    }).toThrow();
  });
});

describe('DD-ECIES §18.6 — Basic-mode envelope round-trip', () => {
  it('the documented 94-byte envelope decrypts to the documented plaintext', () => {
    const envelope = hex(DD_ECIES_TEST_BASIC_ENVELOPE_HEX);
    expect(envelope.length).toBe(94);

    // Parse:
    expect(envelope[0]).toBe(0x01); // version
    expect(envelope[1]).toBe(0x01); // cipherSuite
    expect(envelope[2]).toBe(0x21); // type = Basic
    const ephPub = envelope.subarray(3, 36); // 33 bytes
    const iv = envelope.subarray(36, 48); // 12 bytes
    const tag = envelope.subarray(48, 64); // 16 bytes
    const ct = envelope.subarray(64); // 30 bytes

    expect(ephPub.toString('hex')).toBe(DD_ECIES_TEST_EPHEMERAL_PUBLIC_KEY_HEX);
    expect(iv.toString('hex')).toBe(DD_ECIES_TEST_FIXED_IV_HEX);
    expect(tag.toString('hex')).toBe(DD_ECIES_TEST_BASIC_AUTH_TAG_HEX);
    expect(ct.toString('hex')).toBe(DD_ECIES_TEST_BASIC_CIPHERTEXT_HEX);

    // Reconstruct AAD: version || cipherSuite || type || ephemeralPub
    const aad = Buffer.concat([
      Buffer.from([envelope[0], envelope[1], envelope[2]]),
      ephPub,
    ]);
    expect(aad.toString('hex')).toBe(DD_ECIES_TEST_AAD_BASIC_HEX);

    // Decrypt with the documented recipient private key.
    const recipientPriv = hex(DD_ECIES_TEST_PRIVATE_KEY_HEX);
    const shared33 = secp256k1.getSharedSecret(recipientPriv, ephPub, true);
    const x32 = shared33.subarray(1);
    expect(Buffer.from(x32).toString('hex')).toBe(DD_ECIES_TEST_SHARED_SECRET_HEX);

    const key = hkdf(
      sha256,
      x32,
      new Uint8Array(0),
      ECIES_HKDF_INFO,
      ECIES_HKDF_OUTPUT_LENGTH,
    );
    expect(Buffer.from(key).toString('hex')).toBe(
      DD_ECIES_TEST_DERIVED_SYMMETRIC_KEY_HEX,
    );

    const decipher = createDecipheriv('aes-256-gcm', Buffer.from(key), iv, {
      authTagLength: ECIES_AUTH_TAG_SIZE,
    });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    expect(pt.toString('hex')).toBe(DD_ECIES_TEST_PLAINTEXT_HEX);
  });
});

describe('DD-ECIES §18.7 — WithLength-mode envelope round-trip', () => {
  it('the documented 102-byte envelope decrypts to the documented plaintext', () => {
    const envelope = hex(DD_ECIES_TEST_WITH_LENGTH_ENVELOPE_HEX);
    expect(envelope.length).toBe(102);

    expect(envelope[0]).toBe(0x01);
    expect(envelope[1]).toBe(0x01);
    expect(envelope[2]).toBe(0x42);
    const ephPub = envelope.subarray(3, 36);
    const iv = envelope.subarray(36, 48);
    const tag = envelope.subarray(48, 64);
    const dataLength = envelope.subarray(64, 72);
    const ct = envelope.subarray(72);

    expect(ephPub.toString('hex')).toBe(DD_ECIES_TEST_EPHEMERAL_PUBLIC_KEY_HEX);
    expect(iv.toString('hex')).toBe(DD_ECIES_TEST_FIXED_IV_HEX);
    expect(tag.toString('hex')).toBe(DD_ECIES_TEST_WITH_LENGTH_AUTH_TAG_HEX);
    expect(dataLength.toString('hex')).toBe(DD_ECIES_TEST_DATA_LENGTH_HEX);
    expect(ct.toString('hex')).toBe(DD_ECIES_TEST_BASIC_CIPHERTEXT_HEX);

    // dataLength is a big-endian uint64 — must equal the plaintext length.
    expect(dataLength.readBigUInt64BE(0)).toBe(BigInt(ct.length));
    expect(ct.length).toBe(30);

    // AAD for WithLength: same as Basic but with type byte 0x42, NO data length.
    const aad = Buffer.concat([
      Buffer.from([envelope[0], envelope[1], envelope[2]]),
      ephPub,
    ]);
    expect(aad.toString('hex')).toBe(DD_ECIES_TEST_AAD_WITH_LENGTH_HEX);

    const recipientPriv = hex(DD_ECIES_TEST_PRIVATE_KEY_HEX);
    const shared33 = secp256k1.getSharedSecret(recipientPriv, ephPub, true);
    const x32 = shared33.subarray(1);

    const key = hkdf(
      sha256,
      x32,
      new Uint8Array(0),
      ECIES_HKDF_INFO,
      ECIES_HKDF_OUTPUT_LENGTH,
    );

    const decipher = createDecipheriv('aes-256-gcm', Buffer.from(key), iv, {
      authTagLength: ECIES_AUTH_TAG_SIZE,
    });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    expect(pt.toString('hex')).toBe(DD_ECIES_TEST_PLAINTEXT_HEX);
  });

  it('the WithLength auth tag differs from the Basic auth tag (only the AAD type byte differs)', () => {
    expect(DD_ECIES_TEST_WITH_LENGTH_AUTH_TAG_HEX).not.toBe(
      DD_ECIES_TEST_BASIC_AUTH_TAG_HEX,
    );
  });
});
