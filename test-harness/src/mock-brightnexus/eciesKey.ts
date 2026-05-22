/**
 * Software stand-in for the persistent secp256k1 ECIES key.
 *
 * Mirrors the real `ECIESKeyManager`'s public surface:
 *   - getPublicKey(): returns 65-byte uncompressed (0x04 || x || y).
 *     (RFC §4.5/§4.6: the compressed form is canonical on the wire, but the
 *     real bridge's `GET_PUBLIC_KEY` returns 65-byte uncompressed for both
 *     EBP/1 and BrightLink outputs. We mirror that.)
 *   - decryptEnvelope(envelope): decrypts a DD-ECIES Basic-mode envelope.
 *   - getPrivateKeyRaw(): for known-answer tests.
 */

import { Buffer } from 'node:buffer';
import { randomBytes, createDecipheriv } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

import {
  ECIES_AUTH_TAG_SIZE,
  ECIES_BASIC_FIXED_OVERHEAD,
  ECIES_CIPHER_SUITE_BYTE,
  ECIES_DATA_LENGTH_SIZE,
  ECIES_ENCRYPTION_TYPE,
  ECIES_HKDF_INFO,
  ECIES_HKDF_OUTPUT_LENGTH,
  ECIES_IV_SIZE,
  ECIES_PRIVATE_KEY_LENGTH,
  ECIES_PUBLIC_KEY_LENGTH,
  ECIES_VERSION_BYTE,
} from '../spec/index.js';

export class EciesDecryptError extends Error {
  constructor(public readonly ebp1Error: string) {
    super(ebp1Error);
    this.name = 'EciesDecryptError';
  }
}

export function createMockEciesKey(priv?: Buffer): {
  /** 65-byte uncompressed public key (0x04 || x(32) || y(32)). */
  getPublicKey(): Buffer;
  /** 33-byte compressed public key (rarely needed; for diagnostics). */
  getPublicKeyCompressed(): Buffer;
  /** 32-byte raw private key (test-only). */
  getPrivateKeyRaw(): Buffer;
  /** Decrypts a DD-ECIES Basic-mode (0x21) or WithLength-mode (0x42)
   *  envelope. Returns the plaintext bytes, or throws `EciesDecryptError`
   *  with an `ebp1Error` string matching the EBP/1 §4.10 error vocabulary. */
  decryptEnvelope(envelope: Buffer): Buffer;
} {
  const privRaw = priv ?? Buffer.from(randomBytes(ECIES_PRIVATE_KEY_LENGTH));
  if (privRaw.length !== ECIES_PRIVATE_KEY_LENGTH) {
    throw new Error(
      `secp256k1 private key must be ${ECIES_PRIVATE_KEY_LENGTH} bytes, got ${privRaw.length}`,
    );
  }
  const pubUncompressed = Buffer.from(secp256k1.getPublicKey(privRaw, false));
  const pubCompressed = Buffer.from(secp256k1.getPublicKey(privRaw, true));

  return {
    getPublicKey(): Buffer {
      return pubUncompressed;
    },
    getPublicKeyCompressed(): Buffer {
      return pubCompressed;
    },
    getPrivateKeyRaw(): Buffer {
      return Buffer.from(privRaw);
    },
    decryptEnvelope(envelope: Buffer): Buffer {
      return decryptEnvelope(envelope, privRaw);
    },
  };
}

/** Decrypt a DD-ECIES envelope. Throws `EciesDecryptError` whose
 *  `ebp1Error` matches the spec error vocabulary when something is wrong
 *  with the envelope shape; throws on AES-GCM tag failure with the
 *  generic "Decryption failed" string per RFC §4.10. */
function decryptEnvelope(envelope: Buffer, privRaw: Buffer): Buffer {
  if (envelope.length <= ECIES_BASIC_FIXED_OVERHEAD) {
    throw new EciesDecryptError('Encrypted data too short');
  }

  const version = envelope[0];
  const cipherSuite = envelope[1];
  const encType = envelope[2];

  if (version !== ECIES_VERSION_BYTE) {
    throw new EciesDecryptError('Decryption failed');
  }
  if (cipherSuite !== ECIES_CIPHER_SUITE_BYTE) {
    throw new EciesDecryptError('Decryption failed');
  }

  // Ephemeral key length: 33 (compressed) — strictly. RFC v3 §15
  // (Compatibility posture) says BrightNexus opts out of the DD-ECIES §5.3
  // 65/64-byte tolerance on all decode paths. A non-conformant sender that
  // emits 0x04-prefixed (uncompressed) or raw bytes is rejected immediately
  // rather than allowed to flow into a misshapen ECDH that fails later with
  // a misleading `Decryption failed`.
  const prefix = envelope[3];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new EciesDecryptError('Invalid ephemeral public key format');
  }
  const ephLen = ECIES_PUBLIC_KEY_LENGTH; // 33

  const headerOverhead = 1 + 1 + 1 + ephLen + ECIES_IV_SIZE + ECIES_AUTH_TAG_SIZE;
  if (envelope.length < headerOverhead) {
    throw new EciesDecryptError('Encrypted data too short');
  }

  let offset = 3;
  const ephPub = envelope.subarray(offset, offset + ephLen);
  offset += ephLen;
  const iv = envelope.subarray(offset, offset + ECIES_IV_SIZE);
  offset += ECIES_IV_SIZE;
  const tag = envelope.subarray(offset, offset + ECIES_AUTH_TAG_SIZE);
  offset += ECIES_AUTH_TAG_SIZE;

  let ciphertext: Buffer;
  if (encType === ECIES_ENCRYPTION_TYPE.WITH_LENGTH) {
    if (envelope.length < offset + ECIES_DATA_LENGTH_SIZE) {
      throw new EciesDecryptError('Missing length field');
    }
    const dataLen = envelope.readBigUInt64BE(offset);
    offset += ECIES_DATA_LENGTH_SIZE;
    if (envelope.length < offset + Number(dataLen)) {
      throw new EciesDecryptError('Ciphertext length mismatch');
    }
    ciphertext = envelope.subarray(offset, offset + Number(dataLen));
  } else if (encType === ECIES_ENCRYPTION_TYPE.BASIC) {
    ciphertext = envelope.subarray(offset);
  } else {
    // RFC §4.10 doesn't enumerate "unsupported type" in the error vocabulary;
    // the most-spec-faithful behavior is to fall through to the AES-GCM path,
    // which fails tag verification. We do the same here.
    ciphertext = envelope.subarray(offset);
  }

  // Reconstruct AAD per DD-ECIES §10.2.5 / §10.3.6:
  //   AAD = version || cipherSuite || type || ephemeralPublicKey
  const aad = Buffer.concat([Buffer.from([version, cipherSuite, encType]), ephPub]);

  // ECDH: shared secret = x-coordinate of priv * ephPub.
  // @noble/curves' getSharedSecret(priv, peerPub, true) returns 33 bytes
  // compressed (0x02/0x03 || x). We strip the prefix per DD-ECIES §8.1.
  let shared33: Uint8Array;
  try {
    shared33 = secp256k1.getSharedSecret(privRaw, ephPub, true);
  } catch {
    throw new EciesDecryptError('ECDH failed: empty shared secret');
  }
  if (shared33.length !== 33) {
    throw new EciesDecryptError('ECDH failed: empty shared secret');
  }
  const ikm = shared33.subarray(1); // 32-byte x-coordinate

  // Derive AES key.
  const key = Buffer.from(
    hkdf(sha256, ikm, new Uint8Array(0), ECIES_HKDF_INFO, ECIES_HKDF_OUTPUT_LENGTH),
  );

  // Decrypt with AES-256-GCM.
  const decipher = createDecipheriv('aes-256-gcm', key, iv, {
    authTagLength: ECIES_AUTH_TAG_SIZE,
  });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new EciesDecryptError('Decryption failed');
  }
}
