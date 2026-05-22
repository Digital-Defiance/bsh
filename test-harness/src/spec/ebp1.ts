/**
 * EBP/1 — Enclave Bridge Protocol, version 1.
 *
 * Source of truth: docs/papers/enclave-bridge-protocol.md (the canonical EBP/1
 * specification). All values here are derived from that document; do NOT copy
 * from any implementation source.
 *
 * Every constant carries a `// EBP/1 §X.Y` citation pointing at the section of
 * the spec that defines it. If you change a value here, you are changing the
 * wire contract — make sure the spec changes first.
 */

/** Service identifier returned by HEARTBEAT and METRICS for backward
 *  compatibility with EBP/1 clients that pin on it. // EBP/1 §4.1, §4.4 */
export const EBP1_SERVICE_NAME = 'enclave-bridge';

/** Application identity returned by VERSION/INFO under the new `app` field.
 *  v1-aware clients SHOULD pin on this rather than on `service`.
 *  See README of BrightNexus. */
export const BRIGHTNEXUS_APP_NAME = 'brightnexus';

/** EBP/1 command names (the alphabet defined in §4). The set is fixed; new
 *  commands are added by the BrightLink v1 extension defined in `brightlink.ts`. */
export const EBP1_COMMANDS = {
  HEARTBEAT: 'HEARTBEAT',
  VERSION: 'VERSION',
  INFO: 'INFO', // alias of VERSION per §4.2
  STATUS: 'STATUS',
  METRICS: 'METRICS',
  GET_PUBLIC_KEY: 'GET_PUBLIC_KEY',
  GET_ENCLAVE_PUBLIC_KEY: 'GET_ENCLAVE_PUBLIC_KEY',
  SET_PEER_PUBLIC_KEY: 'SET_PEER_PUBLIC_KEY',
  LIST_KEYS: 'LIST_KEYS',
  ENCLAVE_SIGN: 'ENCLAVE_SIGN',
  ENCLAVE_DECRYPT: 'ENCLAVE_DECRYPT',
  ENCLAVE_GENERATE_KEY: 'ENCLAVE_GENERATE_KEY',
  ENCLAVE_ROTATE_KEY: 'ENCLAVE_ROTATE_KEY',
  ENABLE_TOTP: 'ENABLE_TOTP',
  EXPORT_KEY: 'EXPORT_KEY',
} as const;

export type Ebp1CommandName = (typeof EBP1_COMMANDS)[keyof typeof EBP1_COMMANDS];

/** Reserved key identifiers documented in EBP/1 §4.8. */
export const EBP1_KEY_IDS = {
  ECIES_SECP256K1: 'ecies-secp256k1',
  SECURE_ENCLAVE_P256: 'secure-enclave-p256',
} as const;

/** Key type strings returned by LIST_KEYS. Match the Swift `KeyInfo.KeyType`
 *  raw values verbatim. // EBP/1 §4.8 */
export const EBP1_KEY_TYPES = {
  SECP256K1: 'secp256k1',
  SECURE_ENCLAVE_P256: 'Secure Enclave (P-256)',
} as const;

/** Standard error strings the bridge MUST return for the conditions named in
 *  the spec. We pin on these in tests so a wording drift in the implementation
 *  fails CI rather than silently breaking client error-handling. */
export const EBP1_ERRORS = {
  INVALID_REQUEST_FORMAT: 'Invalid request format', // §4 envelope
  UNKNOWN_COMMAND_PREFIX: 'Unknown command: ', // §4 envelope (suffix is the bad cmd)
  MISSING_OR_INVALID_PUBLIC_KEY: 'Missing or invalid publicKey', // §4.7
  MISSING_OR_INVALID_DATA_TO_SIGN: 'Missing or invalid data to sign', // §4.9
  MISSING_OR_INVALID_DATA_TO_DECRYPT: 'Missing or invalid data to decrypt', // §4.10
  ENCRYPTED_DATA_TOO_SHORT: 'Encrypted data too short', // §4.10
  INVALID_EPHEMERAL_PUBLIC_KEY_FORMAT: 'Invalid ephemeral public key format', // §4.10
  MISSING_LENGTH_FIELD: 'Missing length field', // §4.10 (WithLength only)
  CIPHERTEXT_LENGTH_MISMATCH: 'Ciphertext length mismatch', // §4.10
  ECDH_FAILED_EMPTY_SHARED_SECRET: 'ECDH failed: empty shared secret', // §4.10
  DECRYPTION_FAILED: 'Decryption failed', // §4.10
  ENCLAVE_GENERATE_KEY_NOT_IMPLEMENTED:
    'ENCLAVE_GENERATE_KEY not implemented', // §4.11 (reserved)
  ENCLAVE_ROTATE_KEY_NOT_SUPPORTED:
    'ENCLAVE_ROTATE_KEY not supported on this platform', // §4.12 (reserved)
  MISSING_KEYID_ACCOUNT_ISSUER: 'Missing keyId, account, or issuer', // §4.13
  FAILED_TO_ENABLE_TOTP: 'Failed to enable TOTP for key', // §4.13
  MISSING_KEYID: 'Missing keyId', // §4.14
  TOTP_REQUIRED_OR_INVALID: 'TOTP code required or invalid for this key', // §4.14
  UNKNOWN_KEYID: 'Unknown keyId', // §4.14
} as const;

/** Default socket-discovery order for EBP/1 clients, in the order documented
 *  in EBP/1 §2.2 successor (RFC v3 + BrightNexus README).
 *
 *  This list is consulted by `mock-bsh-client` and serves as the spec for the
 *  real `enclave-bridge-client` to mirror. Each entry is a function of `$HOME`
 *  so it can be resolved per-process.
 *
 *  Order:
 *    1. The new canonical BrightNexus path.
 *    2. The legacy Enclave Bridge path (compat for one major version).
 *
 *  The `${BRIGHTNEXUS_SOCKET}` env override is handled by callers, not here —
 *  this list is the defaulting fallback.
 */
export const EBP1_SOCKET_DISCOVERY_ORDER: ReadonlyArray<(home: string) => string> = [
  (home) => `${home}/.brightchain/brightnexus/brightnexus.sock`,
  (home) => `${home}/.enclave/enclave-bridge.sock`,
];

/** Environment variable a client checks before consulting the discovery
 *  order. Reserved name; intentionally specific so it doesn't collide with
 *  anything else under the BrightChain umbrella. */
export const EBP1_SOCKET_ENV_VAR = 'BRIGHTNEXUS_SOCKET';

/** Server-side `listen(2)` backlog. // EBP/1 §2.1 */
export const EBP1_LISTEN_BACKLOG = 5;

/** Per-connection read buffer size used by the reference server. // EBP/1 §2.4 */
export const EBP1_SERVER_READ_CHUNK = 4096;

/** Brace-terminator framing byte (the closing `}` of a JSON object).
 *  // EBP/1 §3.2 — the reference server scans the connection buffer for this
 *  byte and slices each message there. Clients MUST NOT send nested JSON
 *  objects in requests until the framer is upgraded.
 */
export const EBP1_MESSAGE_TERMINATOR = 0x7d;
