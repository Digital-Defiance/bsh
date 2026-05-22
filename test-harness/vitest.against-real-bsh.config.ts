import { defineConfig } from 'vitest/config';

/**
 * Config for `against-real-bsh` — drives a real bsh binary against
 * `mock-brightnexus` to validate the BrightLink v1 behaviors that live in the
 * shell:
 *
 *   - Lazy LINK_REGISTER on first inject.
 *   - `bsh-inject` builtin encrypts under K_session and emits a valid
 *     LINK_DELIVER JSON request on the EBP/1 socket.
 *   - Per-session monotonic counter on repeated inject calls.
 *   - Fail-closed behavior when the bridge is unreachable.
 *
 * These tests SKIP unless `BSH_HAS_V3_INJECT=1` is set (the env var name
 * is preserved for backward compatibility with earlier invocations). The
 * bsh binary is expected on `$PATH` (or override via `$BSH_BIN`).
 *
 * Invoked via `yarn test:against-real-bsh`.
 */
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/against-real-bsh/**/*.test.ts'],
    testTimeout: 30000,
    hookTimeout: 10000,
  },
});
