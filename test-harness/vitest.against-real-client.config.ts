import { defineConfig } from 'vitest/config';

/**
 * Config for `against-real-client` — drives the real
 * `@digitaldefiance/enclave-bridge-client` package against
 * `mock-brightnexus` in the same Node process. This validates that the
 * production TypeScript client and the spec-derived mock bridge agree at
 * the byte level on:
 *
 *   - LINK_REGISTER envelope construction
 *   - Bilateral HKDF session-key derivation
 *   - Canonical 238-byte transcript layout
 *   - SEP-signed transcript verification (mock SEP, in-process)
 *
 * Unlike `against-real-brightnexus`, this config requires no external
 * service: both halves of the handshake run in the test process.
 *
 * Invoked via `yarn test:against-real-client`.
 */
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/against-real-client/**/*.test.ts'],
    testTimeout: 15000,
    hookTimeout: 10000,
  },
});
