import { defineConfig } from 'vitest/config';

/**
 * Config for `against-real-*` test suites — integration tests that drive
 * a running real component (real BrightNexus, real bsh, real client).
 *
 * Invoked via `yarn test:against-real-brightnexus` etc.
 *
 * These tests `console.log` a clear message and skip if the required real
 * component isn't reachable, so running this config without anything
 * actually running gives a green-but-empty result rather than a hang.
 */
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/against-real-brightnexus/**/*.test.ts'],
    // Long-ish timeout so a slow first registration (SEP key generation
    // can take a moment on first call) doesn't trip the default 5s.
    testTimeout: 30000,
    hookTimeout: 10000,
  },
});
