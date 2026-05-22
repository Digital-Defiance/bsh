# BrightChain test harness

Mocks, executable spec, and known-answer test vectors for the
**bsh + BrightNexus + BrightLink v1** stack.

This package isn't shipped to npm. It exists so we can independently test
each layer of the protocol without booting the entire BrightChain ecosystem.

## What this validates

The BrightLink v1 architecture has three independent participants:

- **bsh** — the reference shell. Owns the BrightLink session and the
  bridge connection. Sends `LINK_DELIVER` for credentials it captures
  via `bsh-inject` (or any other in-process builtin / extension).
- **BrightNexus** — the bridge. Owns the Apple SEP signing key, mints
  sessions, decrypts deliveries, surfaces credentials in the menu bar.
- **enclave-bridge-client** — the production TypeScript client.

The harness contains a from-scratch implementation of each role. The
"real ↔ mock" matrix lets us catch any disagreement between a real
participant and the spec without standing up a full three-way test bed.

## Layout

```
src/
├── spec/                       Executable spec — every constant carries
│   ├── ebp1.ts                 an RFC §X.Y citation. Single source of
│   ├── ecies.ts                truth that all three mocks consult.
│   ├── geo.ts                  (geo is reserved in v1)
│   ├── brightlink.ts           BrightLink v1 — protocol constants,
│   │                           transcript builder, deriveSessionKey,
│   │                           buildDeliverAad.
│   └── index.ts
├── shared/
│   ├── known-answer-vectors.ts Byte-exact deterministic test vectors.
│   └── test-client.ts          Minimal EBP/1 client with brace-counting
│                               parser. Used by tests.
├── mock-brightnexus/           In-process mock of the BrightNexus bridge.
│   ├── eciesKey.ts             Software secp256k1 key + DD-ECIES decrypt.
│   ├── softSep.ts              Software P-256 SEP stand-in.
│   ├── handlers.ts             EBP/1 + BrightLink command dispatch
│   │                           (REGISTER, DELIVER).
│   ├── socketServer.ts         Unix-socket server + brace-terminator
│   │                           framing.
│   ├── types.ts                Public interfaces.
│   └── index.ts                Public surface (MockBrightNexus class).
└── mock-bsh-client/            In-process mock of a v1-aware shell.
    ├── discovery.ts            Bridge socket discovery.
    ├── types.ts                Public interfaces.
    └── index.ts                MockBshClient — register, ingestCredential
                                helper, SEP-pinned transcript verification.

tests/
├── unit/                                  Self-contained spec tests.
│   ├── spec-shape.test.ts                 Internal consistency.
│   ├── dd-ecies-known-answer.test.ts      DD-ECIES §18 vectors.
│   ├── link-session-key.test.ts           §4.5.2 K_session pin.
│   └── mock-brightnexus.test.ts           Bridge-mock surface.
├── against-real-brightnexus/              Real Swift bridge driven by
│   ├── link-register.test.ts              mock-bsh-client. Validates
│   ├── link-deliver.test.ts               the Swift implementation
│   ├── link-policy.test.ts                matches the spec.
│   └── manual-credential-display.test.ts
├── against-real-client/                   Real TypeScript client driven
│   └── link-register.test.ts              by mock-brightnexus. Validates
│                                          the production client matches.
└── against-real-bsh/                      Real bsh binary driven against
    └── link-register-and-deliver.test.ts  mock-brightnexus.
```

Total: 81 unit + 9 against-real-client + 24 against-real-brightnexus + 4 against-real-bsh = 118 tests.

## The spec module is the source of truth

Every constant in `src/spec/*.ts` has an inline `// RFC §X.Y` or
`// DD-ECIES §X.Y` citation. The three mocks and the real implementations
all derive their behavior from the spec; they never share a crypto helper
with each other. This is intentional: if a mock and the real code share
a helper, they share its bugs. Independent re-derivation catches drift.

## What v1 looks like on the wire

BrightLink v1 is JSON on a Unix domain socket, with a hardware-anchored
handshake that derives a per-session AES-256-GCM key. Three properties
matter:

1. **Bilateral HKDF.** Both sides contribute entropy to the session
   key. Neither can unilaterally choose it.

2. **SEP-signed transcript.** A 238-byte canonical record of the
   handshake — header, both nonces, both public keys, timestamp, TTL —
   is signed by the bridge's Secure Enclave P-256 key. The shell
   verifies the signature and pins the SEP key on first use.

3. **Length-prefixed AAD.** Every `LINK_DELIVER` ciphertext binds
   direction, monotonic counter, type, and context into the GCM
   authentication tag. Replay an old ciphertext, alter the type or
   context, switch direction tags — every one fails the tag check.

Wire constants live in `src/spec/brightlink.ts`. Tests in
`tests/unit/link-session-key.test.ts` and
`tests/unit/link-deliver-aad.test.ts` lock those constants in.

## Running tests

```sh
yarn install
yarn test                        # unit + interop (no external state)
yarn typecheck                   # TypeScript only
```

Real-component suites are gated behind explicit selection because they
require external state:

```sh
yarn test:against-real-brightnexus           # requires BrightNexus.app running
yarn test:against-real-client                # mock-brightnexus + real production client
BSH_HAS_V3_INJECT=1 BSH_BIN=/Volumes/Code/bsh/Src/bsh \
  yarn test:against-real-bsh                 # real bsh + mock-brightnexus
```

## Manual UI verification

For visually confirming the BrightNexus credentials menu populates correctly:

```sh
BRIGHTNEXUS_MANUAL_UI=1 yarn test:against-real-brightnexus
```

This holds two credentials live for 30 seconds while you click the menu bar
icon. After the test exits, credentials persist for their declared `ttl`
(RFC §4.6, §5) — they are NOT evicted by connection close.

## Known-answer vectors

Byte-exact deterministic vectors any conforming implementation MUST match:

- **DD-ECIES §6.6** — secp256k1 keypair from the BIP39 test mnemonic.
- **DD-ECIES §7.6** — ECDSA signature with RFC 6979 deterministic nonce.
- **DD-ECIES §8.4** — ECDH shared secret + HKDF-SHA256 derivation.
- **DD-ECIES §18.5** — AES-256-GCM standalone encrypt/decrypt round-trip.
- **DD-ECIES §18.6** — Basic-mode (0x21) full envelope (94 bytes).
- **DD-ECIES §18.7** — WithLength-mode (0x42) full envelope (102 bytes).
- **BrightLink v1 §4.5.2** — bilateral-HKDF K_session derivation.
- **BrightLink v1 §4.5.3** — canonical 238-byte transcript layout.

A future Swift, Rust, or other-language implementation can run these
vectors as a known-answer test before being declared interoperable.

## Reference documents

- `docs/rfc-brightlink.md` — BrightLink v1 RFC.
- `docs/papers/enclave-bridge-protocol.md` — EBP/1 specification.
- `docs/papers/dd-ecies-specification.md` — DD-ECIES wire format.
