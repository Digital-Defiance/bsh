import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // Real-component tests are gated behind explicit selection; they require
    // an external service (real BrightNexus, real bsh, real client) to be
    // running and would otherwise fail or hang during CI.
    exclude: [
      'tests/against-real-brightnexus/**',
      'tests/against-real-client/**',
      'tests/against-real-bsh/**',
      'node_modules/**',
      'dist/**',
    ],
  },
});
