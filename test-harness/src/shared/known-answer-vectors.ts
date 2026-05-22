/**
 * Known-answer test vectors.
 *
 * These are byte-exact deterministic test inputs and outputs, sourced from
 * specification documents. They exist so an implementation that quietly
 * deviates from the spec — wrong HKDF info string, wrong byte order, wrong
 * field offset — fails CI with an obvious mismatch instead of failing
 * mysteriously at first interop attempt with a real peer.
 *
 * Sources (cited inline per vector):
 *   - DD-ECIES-SPEC-v1.0 §18  (DD-ECIES test vectors)
 *   - BrightLink RFC §4.5.0    (re-affirms the DD-ECIES §18.6 vector for use
 *                              in LINK_REGISTER outer envelopes)
 *
 * Hex encoding throughout. Convert with `Buffer.from(hex, 'hex')`.
 */

// ────────────────────────────────────────────────────────────────────────────
// DD-ECIES §6.6 — Mnemonic-to-key derivation
// ────────────────────────────────────────────────────────────────────────────

/** The well-known BIP39 test mnemonic used as the identity throughout the
 *  DD-ECIES test vectors. // DD-ECIES §6.6 */
export const DD_ECIES_BIP39_TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon abandon abandon abandon ' +
  'abandon abandon abandon abandon abandon abandon abandon art';

/** Empty BIP39 passphrase. // DD-ECIES §6.6 */
export const DD_ECIES_BIP39_TEST_PASSPHRASE = '';

/** Derivation path m/44'/60'/0'/0/0. // DD-ECIES §6.3.1 */
export const DD_ECIES_HD_DERIVATION_PATH = "m/44'/60'/0'/0/0";

/** 64-byte seed produced by mnemonicToSeed("abandon...art", ""). */
export const DD_ECIES_TEST_SEED_HEX =
  '408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840';

/** 32-byte private key after BIP32/BIP44 derivation along m/44'/60'/0'/0/0. */
export const DD_ECIES_TEST_PRIVATE_KEY_HEX =
  '1053fae1b3ac64f178bcc21026fd06a3f4544ec2f35338b001f02d1d8efa3d5f';

/** 33-byte compressed secp256k1 public key derived from the private key.
 *  Begins with 0x02 (even y-coordinate). */
export const DD_ECIES_TEST_PUBLIC_KEY_COMPRESSED_HEX =
  '02dc286c821c7490afbe20a79d13123b9f41f3d7ef21e4a9caacd22f5983b28eca';

// ────────────────────────────────────────────────────────────────────────────
// DD-ECIES §7.6 — ECDSA signature
// ────────────────────────────────────────────────────────────────────────────

export const DD_ECIES_ECDSA_TEST_MESSAGE_UTF8 = 'DD-ECIES signature test vector';
export const DD_ECIES_ECDSA_TEST_MESSAGE_HEX =
  '44442d4543494553207369676e6174757265207465737420766563746f72';

/** SHA-256 of the message bytes. */
export const DD_ECIES_ECDSA_TEST_HASH_HEX =
  'a1fc0896b3b1a9b1e0eaf1434a04d26e679a422a8d21a9104f458bb7bf6a2d2e';

/** 64-byte compact ECDSA signature (r || s). RFC 6979 deterministic nonce. */
export const DD_ECIES_ECDSA_TEST_SIGNATURE_HEX =
  '6596fb18720a906b5b20eaaa259bfecaef35555208c15c61022216f373a306f9' +
  '0deb13d6cfd91e73b405a46a131fc98f13e410c1c89d3a960ee29f489da25e9d';

// ────────────────────────────────────────────────────────────────────────────
// DD-ECIES §8.4 — ECDH shared secret + HKDF key derivation
// ────────────────────────────────────────────────────────────────────────────

/** Ephemeral private key derived as SHA-256("DD-ECIES-ECDH-test-vector-ephemeral").
 *  Provided for reproducibility — these vectors avoid randomness. */
export const DD_ECIES_TEST_EPHEMERAL_PRIVATE_KEY_HEX =
  'bc4313f0c6e23ae0366e40d80387f49a2e4f64069dcb5a447f22dabefb79dc2f';

/** 33-byte compressed ephemeral public key. */
export const DD_ECIES_TEST_EPHEMERAL_PUBLIC_KEY_HEX =
  '02fbb6f2f3ee200f9cd9f33b86e7de3412eb9aee09f6b10709a595f5ede231494b';

/** ECDH shared secret = 32-byte x-coordinate of the shared point. */
export const DD_ECIES_TEST_SHARED_SECRET_HEX =
  '0933f1546610b5bdbe4349b25b783d07fd5185b84b3efee2e92dc9bf2a034a11';

/** HKDF info string used for ECIES outer envelope key derivation. */
export const DD_ECIES_HKDF_INFO_UTF8 = 'ecies-v2-key-derivation';

/** HKDF info string in hex (UTF-8 bytes). 23 bytes. */
export const DD_ECIES_HKDF_INFO_HEX = '65636965732d76322d6b65792d64657269766174696f6e';

/** 32-byte AES-256-GCM key derived from the shared secret via HKDF-SHA256
 *  with empty salt and the info string above. */
export const DD_ECIES_TEST_DERIVED_SYMMETRIC_KEY_HEX =
  '7c4fd382f540c37c6bee1e9c24a5d15e8a7a8f474a4882f4c8606520f2b801ab';

// ────────────────────────────────────────────────────────────────────────────
// DD-ECIES §18.5 — AES-256-GCM standalone encrypt/decrypt
// ────────────────────────────────────────────────────────────────────────────

/** Fixed IV used in §18.5–§18.7 for reproducibility. First 12 bytes of
 *  SHA-256("DD-ECIES-AES-GCM-test-vector-iv"). */
export const DD_ECIES_TEST_FIXED_IV_HEX = '31fe1b062e5639622cfc0439';

/** Common plaintext used in §18.5–§18.7. */
export const DD_ECIES_TEST_PLAINTEXT_UTF8 = 'DD-ECIES test vector plaintext';
export const DD_ECIES_TEST_PLAINTEXT_HEX =
  '44442d4543494553207465737420766563746f7220706c61696e74657874';

/** AAD for the §18.5 standalone AES-GCM test (Basic-mode-shaped, type 0x21).
 *  Layout: version(0x01) || cipherSuite(0x01) || type(0x21) || ephemeralPub(33B). */
export const DD_ECIES_TEST_AAD_BASIC_HEX =
  '01012102fbb6f2f3ee200f9cd9f33b86e7de3412eb9aee09f6b10709a595f5ede231494b';

/** Output of AES-256-GCM(K, IV, AAD, plaintext) for the §18.5 test. */
export const DD_ECIES_TEST_BASIC_CIPHERTEXT_HEX =
  'f3c70450f1ac074e93508eb3caed91a900ebc463d4eaa78c4c56389f36ee';
export const DD_ECIES_TEST_BASIC_AUTH_TAG_HEX = 'e6dbf735d3ef9a4235d5513f9e8829ce';

// ────────────────────────────────────────────────────────────────────────────
// DD-ECIES §18.6 — Basic mode (0x21) full envelope
// ────────────────────────────────────────────────────────────────────────────

/**
 * Complete 94-byte Basic-mode envelope for the test plaintext, addressed to
 * the test public key, using the test ephemeral key and fixed IV above.
 *
 *   01           version
 *   01           cipherSuite
 *   21           encryptionType (Basic)
 *   02fbb6...    ephemeralPublicKey (33 bytes compressed, prefix 0x02)
 *   31fe1b...    iv (12 bytes)
 *   e6db...      authTag (16 bytes)
 *   f3c7...      ciphertext (30 bytes)
 *
 * Total: 64 (fixed overhead) + 30 (ciphertext) = 94 bytes.
 *
 * BrightLink v1 §4.5.0 names this as the canonical interop test vector for
 * LINK_REGISTER outer envelopes. Any from-scratch implementation MUST pass
 * this round-trip in CI before being considered conformant.
 */
export const DD_ECIES_TEST_BASIC_ENVELOPE_HEX =
  '01012102fbb6f2f3ee200f9cd9f33b86e7de3412eb9aee09f6b10709a595f5ede231494b' +
  '31fe1b062e5639622cfc0439' +
  'e6dbf735d3ef9a4235d5513f9e8829ce' +
  'f3c70450f1ac074e93508eb3caed91a900ebc463d4eaa78c4c56389f36ee';

// ────────────────────────────────────────────────────────────────────────────
// DD-ECIES §18.7 — WithLength mode (0x42) full envelope
// ────────────────────────────────────────────────────────────────────────────

/** AAD for the WithLength test. Same structure as Basic but type byte = 0x42.
 *  The 8-byte data length field is NOT part of the AAD. */
export const DD_ECIES_TEST_AAD_WITH_LENGTH_HEX =
  '01014202fbb6f2f3ee200f9cd9f33b86e7de3412eb9aee09f6b10709a595f5ede231494b';

/** Auth tag from the §18.7 round (different from §18.6 because the AAD type
 *  byte differs even though the symmetric key, IV, and plaintext are identical). */
export const DD_ECIES_TEST_WITH_LENGTH_AUTH_TAG_HEX =
  'bff70cfe6ac4c0df708859336ef6763c';

/** Big-endian uint64 encoding of the plaintext length (30 = 0x1e). */
export const DD_ECIES_TEST_DATA_LENGTH_HEX = '000000000000001e';

/**
 * Complete 102-byte WithLength-mode envelope.
 *
 *   01           version
 *   01           cipherSuite
 *   42           encryptionType (WithLength)
 *   02fbb6...    ephemeralPublicKey
 *   31fe1b...    iv
 *   bff7...      authTag
 *   00000...001e dataLength (uint64 big-endian, value 30)
 *   f3c7...      ciphertext
 *
 * Total: 72 (fixed overhead) + 30 (ciphertext) = 102 bytes.
 */
export const DD_ECIES_TEST_WITH_LENGTH_ENVELOPE_HEX =
  '01014202fbb6f2f3ee200f9cd9f33b86e7de3412eb9aee09f6b10709a595f5ede231494b' +
  '31fe1b062e5639622cfc0439' +
  'bff70cfe6ac4c0df708859336ef6763c' +
  '000000000000001e' +
  'f3c70450f1ac074e93508eb3caed91a900ebc463d4eaa78c4c56389f36ee';

// ────────────────────────────────────────────────────────────────────────────
// BrightLink v1 — derived bilateral-HKDF vector
// ────────────────────────────────────────────────────────────────────────────

/**
 * The RFC v3 §4.5.2 bilateral-HKDF derivation has no published canonical
 * answer (it's a v3-specific construction). Below is a deterministic test
 * vector derived from fixed inputs that the harness uses as its own
 * known-answer for `K_session`. The expected output bytes are computed by
 * `tests/unit/link-session-key.test.ts` using @noble/hashes' HKDF-SHA256
 * implementation and assert-pinned at first run. If you change any of these
 * inputs OR the derivation, the assertion catches the drift.
 *
 * The inputs are derived from `SHA-256("BrightLink v1 test <field>")` so they're
 * reproducible without RNG.
 */
export const LINK_V1_TEST_INPUTS = {
  // SHA-256("BrightLink v1 test clientNonce")[0..16]
  clientNonceHex: 'b1b8a3a3eb89dc8c1ad7b89f3aac1c83',
  // SHA-256("BrightLink v1 test sessionId")[0..16]
  sessionIdHex: 'aef7e09e3ee0c4886a25b0bbabb2cf94',
  // SHA-256("BrightLink v1 test clientShare")
  clientShareHex: '5c01dee7d5e1b1a06ee20cd97a05dba9b9d3a35d76d72c39a8f8b2e6f6c5d2eb',
  // SHA-256("BrightLink v1 test bridgeShare")
  bridgeShareHex: '8d6f0a1b88ac1c0c6c6a4727d99cae93d1e3789a6b0f5a9c5b5fdd7e4d091b3a',
  /** issuedAtBd: a fixed BrightDate scalar for testing. May 21 2026 ≈ J2000+9637.
   *  The transcript-construction code rounds (issuedAtBd*86400) to integer. */
  issuedAtBd: 9637.5,
  /** Bridge clock at test time: 1747915200 = 2025-05-22 12:00:00 UTC.
   *  (Held fixed for known-answer; mocks override with Date.now() in real runs.) */
  bridgeIssuedAtUnix: 1747915200,
  /** TTL granted: 1 hour (well below the 8h cap). */
  ttlSeconds: 3600,
} as const;

/**
 * The expected `K_session` for those inputs is asserted at run time by
 * `tests/unit/link-session-key.test.ts`. We don't hardcode it here because
 * any value we'd write down without first computing it would be a guess.
 * The test computes it once via @noble/hashes and snapshots the value.
 *
 * Once snapshotted, the file becomes the binding test vector for any future
 * porting effort: a Swift implementation of the same derivation MUST produce
 * the same 32 bytes when fed `LINK_V1_TEST_INPUTS`.
 */
