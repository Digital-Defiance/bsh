/**
 * Software stand-in for Apple's Secure Enclave (SEP) P-256 signing key.
 *
 * Mimics the public surface of `SecureEnclaveKeyManager` in the real bridge:
 *
 *   - getPublicKeyData(): returns 65-byte uncompressed X9.63 public key.
 *   - sign(data): SHA-256s the data internally (matching Apple CryptoKit's
 *                 `priv.signature(for:)` behavior per EBP/1 §4.9), then
 *                 ECDSA-signs the digest and returns DER bytes.
 *
 * "SEP" is in the name only — we hold the private key in process memory.
 * For the harness this is fine; the spec doesn't require hardware to verify
 * its wire format. Real BrightNexus has the real SEP guarantees.
 */

import { Buffer } from 'node:buffer';
import { createSign, createPrivateKey, createPublicKey, generateKeyPairSync, KeyObject } from 'node:crypto';

/**
 * Construct a software SEP stand-in. If `priv` is omitted, generates a fresh
 * P-256 keypair. Returns an object with `publicKey()` and `sign()` methods
 * matching the contract of the real `SecureEnclaveKeyManager`.
 */
export function createSoftSep(priv?: Buffer): {
  /** 65-byte uncompressed X9.63 public key (0x04 || x || y). */
  publicKey(): Buffer;
  /** SHA-256-then-ECDSA-sign the input and return DER-encoded signature. */
  sign(data: Buffer): Buffer;
  /** Raw 32-byte private key (for known-answer tests that pin the key). */
  privateKeyRaw(): Buffer;
} {
  const { keyObject, privRaw } = createOrLoadKeyPair(priv);

  return {
    publicKey(): Buffer {
      // Export as 65-byte uncompressed point. Node's KeyObject doesn't have
      // a single one-shot for that; we export DER and extract the bit string.
      const pubKey = createPublicKey(keyObject);
      const der = pubKey.export({ format: 'der', type: 'spki' });
      // SPKI for P-256 carries the 65-byte uncompressed point as the BIT
      // STRING value at the end. Extract the last 65 bytes — the SPKI
      // header for P-256 is a fixed 26-byte prefix, but it's safer to
      // pull the trailing 65 bytes since BIT STRING content is at the end.
      // Sanity check: total SPKI is 91 bytes, last 65 are the uncompressed point.
      return Buffer.from(der.subarray(der.length - 65));
    },
    sign(data: Buffer): Buffer {
      // Match Apple CryptoKit's `priv.signature(for:)`: hash with SHA-256
      // internally, then ECDSA-sign the digest. Node's createSign does the
      // hashing for us when given the message; the result is DER-encoded
      // by default (matching `derRepresentation`).
      const signer = createSign('SHA256');
      signer.update(data);
      signer.end();
      return signer.sign({ key: keyObject, dsaEncoding: 'der' });
    },
    privateKeyRaw(): Buffer {
      return privRaw;
    },
  };
}

function createOrLoadKeyPair(priv: Buffer | undefined): {
  keyObject: KeyObject;
  privRaw: Buffer;
} {
  if (priv === undefined) {
    // Fresh keypair.
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    // Re-derive the raw 32-byte scalar from the JWK so callers can pin it.
    const jwk = privateKey.export({ format: 'jwk' });
    const dB64u = jwk.d as string;
    const privRaw = Buffer.from(b64uToBytes(dB64u));
    if (privRaw.length !== 32) {
      throw new Error(`expected 32-byte P-256 scalar, got ${privRaw.length}`);
    }
    return { keyObject: privateKey, privRaw };
  }

  // Load a fixed scalar by constructing a JWK with the supplied `d` and
  // deriving x,y from it — but Node's createPrivateKey JWK form requires
  // x,y too, so we have to compute them. Use @noble/curves which is
  // already a harness dependency.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { p256 } = require('@noble/curves/p256');
  if (priv.length !== 32) {
    throw new Error(`P-256 priv must be 32 bytes, got ${priv.length}`);
  }
  const pubUncompressed = p256.getPublicKey(priv, /* compressed */ false);
  // pubUncompressed is 65 bytes: 0x04 || x(32) || y(32)
  const x = Buffer.from(pubUncompressed.subarray(1, 33));
  const y = Buffer.from(pubUncompressed.subarray(33, 65));

  const jwk = {
    kty: 'EC' as const,
    crv: 'P-256' as const,
    d: bytesToB64u(priv),
    x: bytesToB64u(x),
    y: bytesToB64u(y),
  };
  const keyObject = createPrivateKey({ key: jwk, format: 'jwk' });
  return { keyObject, privRaw: Buffer.from(priv) };
}

function bytesToB64u(b: Uint8Array): string {
  return Buffer.from(b).toString('base64url');
}

function b64uToBytes(s: string): Uint8Array {
  return Buffer.from(s, 'base64url');
}
