/**
 * DD-ECIES wire format constants.
 *
 * These values are normatively pinned by:
 *   - DD-ECIES-SPEC-v1.0 (the canonical specification of `@digitaldefiance/ecies-lib`
 *     and `@digitaldefiance/node-ecies-lib`)
 *   - BrightLink RFC §4.5.0 (which restates the subset that affects BrightLink)
 *
 * If DD-ECIES and the live `node-ecies-lib` source disagree, the source wins
 * and DD-ECIES is the bug to fix. We import the live `ECIES` constants object
 * from the library and re-export it after asserting that every value matches
 * the spec — that way a divergence between library and spec fails *our* tests,
 * not someone else's interop.
 *
 * See `tests/unit/ecies-spec.test.ts` for the assertions.
 */

// We reference DD-ECIES sections inline. The full citation notation
// "DD-ECIES §X.Y" refers to the canonical specification document.

// ────────────────────────────────────────────────────────────────────────────
// Curve and key formats (DD-ECIES §5)
// ────────────────────────────────────────────────────────────────────────────

/** secp256k1 — DD-ECIES §5.1 */
export const ECIES_CURVE_NAME = 'secp256k1';

/** Compressed public key length: 1 prefix byte (0x02 / 0x03) + 32-byte x.
 *  DD-ECIES §5.2: this is the canonical form on the wire.
 */
export const ECIES_PUBLIC_KEY_LENGTH = 33;

/** Raw x-coordinate length without prefix. DD-ECIES §5.2 */
export const ECIES_RAW_PUBLIC_KEY_LENGTH = 32;

/** Default compressed-key prefix for even y-coordinate. DD-ECIES §5.2 */
export const ECIES_PUBLIC_KEY_MAGIC = 0x02;

/** Uncompressed public key length: 0x04 prefix + 32-byte x + 32-byte y.
 *  Decoders MUST accept this for backward compatibility per DD-ECIES §5.3.
 *  Senders MUST emit only the 33-byte compressed form.
 */
export const ECIES_UNCOMPRESSED_PUBLIC_KEY_LENGTH = 65;

/** Raw (no prefix) public key length. Decoders MUST accept this per §5.3. */
export const ECIES_BARE_PUBLIC_KEY_LENGTH = 64;

/** Private key length. DD-ECIES §5.4 */
export const ECIES_PRIVATE_KEY_LENGTH = 32;

// ────────────────────────────────────────────────────────────────────────────
// Symmetric cipher (DD-ECIES §9)
// ────────────────────────────────────────────────────────────────────────────

/** AES-256-GCM. DD-ECIES §9.1 */
export const ECIES_SYMMETRIC_ALGORITHM = 'aes-256-gcm';
export const ECIES_SYMMETRIC_KEY_BITS = 256;
export const ECIES_SYMMETRIC_KEY_SIZE = 32;

/** 12-byte IV (96-bit nonce). DD-ECIES §9.2.
 *  CRITICAL: the canonical wire format uses 12 bytes. A 16-byte IV variant
 *  exists only as a deprecated server-originated helper that has been removed
 *  from BrightNexus per RFC v3 §5.2. Do not use 16-byte IVs.
 */
export const ECIES_IV_SIZE = 12;

/** Authentication tag size. DD-ECIES §9.3 */
export const ECIES_AUTH_TAG_SIZE = 16;

// ────────────────────────────────────────────────────────────────────────────
// HKDF for the outer ECIES envelope (DD-ECIES §8.2)
// ────────────────────────────────────────────────────────────────────────────

/** HKDF info string for the AES-256-GCM key derivation that protects the
 *  ECIES outer envelope. DD-ECIES §8.2.
 *
 *  CRITICAL: this is used by `ENCLAVE_DECRYPT` envelopes and by LINK_REGISTER's
 *  outer envelope. It is NOT the BrightLink session-key info string — that is in
 *  `brightlink.ts` as `LINK_SESSION_KEY_HKDF_INFO`.
 */
export const ECIES_HKDF_INFO = 'ecies-v2-key-derivation';

/** Empty salt. DD-ECIES §8.2 explicitly specifies an empty salt. */
export const ECIES_HKDF_SALT = new Uint8Array(0);

/** HKDF output length matches the AES-256-GCM key size. DD-ECIES §8.2 */
export const ECIES_HKDF_OUTPUT_LENGTH = 32;

// ────────────────────────────────────────────────────────────────────────────
// Wire format header bytes (DD-ECIES §17 + §10)
// ────────────────────────────────────────────────────────────────────────────

/** Protocol version. The only registered value. DD-ECIES §17.1 */
export const ECIES_VERSION_BYTE = 0x01;

/** Cipher suite identifier: `Secp256k1_Aes256Gcm_Sha256`. DD-ECIES §17.2 */
export const ECIES_CIPHER_SUITE_BYTE = 0x01;

/** Encryption type bytes. DD-ECIES §17.3 */
export const ECIES_ENCRYPTION_TYPE = {
  /** Basic single-recipient mode. No data length prefix. DD-ECIES §10.2 */
  BASIC: 0x21,
  /** WithLength single-recipient mode. 8-byte big-endian length after tag. §10.3 */
  WITH_LENGTH: 0x42,
  /** Multiple-recipient mode. §11. NOT supported by the BrightLink surface. */
  MULTIPLE: 0x63,
} as const;

export type EciesEncryptionType =
  (typeof ECIES_ENCRYPTION_TYPE)[keyof typeof ECIES_ENCRYPTION_TYPE];

/** Fixed overhead for Basic mode (§10.2.4):
 *    version(1) + cipherSuite(1) + type(1) + ephemeralPub(33) + iv(12) + tag(16)
 */
export const ECIES_BASIC_FIXED_OVERHEAD = 64;

/** Fixed overhead for WithLength mode (§10.3.5): Basic + 8-byte length field. */
export const ECIES_WITH_LENGTH_FIXED_OVERHEAD = 72;

/** Data length field size for WithLength mode (big-endian uint64). §10.3.4 */
export const ECIES_DATA_LENGTH_SIZE = 8;
