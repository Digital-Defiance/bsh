/**
 * `BridgeIdentity` interface and the mock's software-backed implementation.
 *
 * The real bridge uses one of three implementations depending on the host
 * platform (RFC §6.1):
 *
 *   - `SepBridgeIdentity` on macOS Apple Silicon (Secure Enclave-resident).
 *   - `Tpm2BridgeIdentity` on Linux with TPM2 (TPM2 NV-resident via tpm2-tss).
 *   - `FileBridgeIdentity` everywhere else (software P-256 key on disk).
 *
 * The mock exposes a `SoftwareBridgeIdentity` that wraps the existing
 * `softSep` (which is already a software P-256 signer used for the §4.5
 * registration transcript). It satisfies the `BridgeIdentity` contract and
 * reports its kind as `FileBridgeIdentity` so any client that gates on
 * "is the bridge identity hardware-backed?" sees the right answer in tests.
 *
 * Key id format (§6.1): `"p256:<base64(SHA-256(pub))[0..16]>"`.
 */

import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';

import {
  LINK_BRIDGE_IDENTITY_KINDS,
  type LinkBridgeIdentityKind,
} from '../spec/index.js';
import { createSoftSep } from './softSep.js';

export interface BridgeIdentity {
  /** Stable id derived from the public key. RFC §6.1. */
  keyId(): string;

  /** 65-byte uncompressed P-256 public key (X9.63 form). */
  publicKey(): Buffer;

  /** SHA-256-then-ECDSA-sign the data; returns DER-encoded signature. */
  sign(data: Buffer): Buffer;

  /** Which `BridgeIdentity` implementation this is. RFC §6.1.
   *  Surfaced through the §4.5 transcript and the bridge's startup log so
   *  clients can refuse to register against software-backed bridges. */
  kind(): LinkBridgeIdentityKind;
}

/** Compute the §6.1 key id from a 65-byte uncompressed P-256 public key. */
export function computeKeyId(pubUncompressed65: Buffer): string {
  if (pubUncompressed65.length !== 65) {
    throw new Error(
      `bridge identity public key must be 65 bytes uncompressed, got ${pubUncompressed65.length}`,
    );
  }
  const hash = createHash('sha256').update(pubUncompressed65).digest();
  // Take the first 16 bytes, base64-encode without padding.
  const prefix16 = hash.subarray(0, 16);
  return `p256:${prefix16.toString('base64url').replace(/=+$/, '')}`;
}

/** Software-backed `BridgeIdentity` for the harness. Wraps `softSep`. */
export class SoftwareBridgeIdentity implements BridgeIdentity {
  private readonly sep: ReturnType<typeof createSoftSep>;
  private readonly cachedKeyId: string;
  private readonly cachedPub: Buffer;

  constructor(priv?: Buffer) {
    this.sep = createSoftSep(priv);
    this.cachedPub = this.sep.publicKey();
    this.cachedKeyId = computeKeyId(this.cachedPub);
  }

  keyId(): string {
    return this.cachedKeyId;
  }

  publicKey(): Buffer {
    return this.cachedPub;
  }

  sign(data: Buffer): Buffer {
    return this.sep.sign(data);
  }

  kind(): LinkBridgeIdentityKind {
    // The mock is software-backed; tests that need to assert
    // "the bridge is hardware-backed" can swap this implementation.
    return LINK_BRIDGE_IDENTITY_KINDS.FILE;
  }
}
