/**
 * Manual visual-confirmation test for the BrightNexus menu bar credential UI.
 *
 * This test connects, registers, ingests two credentials, and HOLDS the
 * connection for 30 seconds. While it sleeps, click the BrightNexus menu
 * bar icon — the "Credentials" submenu should show two entries with TTL
 * countdowns ticking. When the test exits and the connection closes, the
 * credentials should disappear immediately (per `BridgeProtocolHandler.deinit`).
 *
 * Skip behavior: this test is GATED behind the BRIGHTNEXUS_MANUAL_UI env var
 * because it sleeps for 30s and is meaningless in CI. Run it explicitly:
 *
 *   BRIGHTNEXUS_MANUAL_UI=1 yarn test:against-real-brightnexus
 */

import { describe, it, beforeEach, afterEach } from 'vitest';
import { existsSync } from 'node:fs';

import { MockBshClient, discoverSocketPath } from '../../src/mock-bsh-client/index.js';

function findRealBridgeSocket(): string | null {
  const explicit = process.env['BRIGHTNEXUS_TEST_SOCKET'];
  if (explicit && existsSync(explicit)) return explicit;
  return discoverSocketPath();
}

const enabled = process.env['BRIGHTNEXUS_MANUAL_UI'] === '1';
const socketPath = findRealBridgeSocket();

let client: MockBshClient | null = null;

beforeEach(async () => {
  if (!enabled || !socketPath) return;
  client = new MockBshClient();
  await client.connect(socketPath);
  await client.register({ ttlSeconds: 1800 });
});

afterEach(async () => {
  if (client) {
    await client.disconnect();
    client = null;
  }
});

describe('BrightNexus menu bar — manual credential-display verification', () => {
  it.runIf(enabled && socketPath !== null)(
    'populates the menu bar with two credentials for 30 seconds',
    async () => {
      console.log('\n[manual] Ingesting two credentials.');
      console.log('[manual] Open the BrightNexus menu bar — you should see "Credentials  (2)".\n');

      await client!.ingestCredential({
        type: 'ephemeral-auth',
        context: 'http://localhost:3005',
        body: {
          ttl: 600,
          username: 'alice',
          password: 'p@ssw0rd',
          email: 'alice@example.com',
        },
      });

      await client!.ingestCredential({
        type: 'db-connection',
        context: 'postgres://prod-db',
        body: {
          ttl: 600,
          engine: 'postgres',
          host: 'prod-db.internal',
          port: 5432,
          user: 'svc',
          pass: 'secret-sauce',
        },
      });

      console.log('[manual] Holding for 30s. Click the menu bar icon now.');
      await new Promise((resolve) => setTimeout(resolve, 30_000));
      console.log(
        '[manual] Disconnecting — credentials should REMAIN in the menu (RFC §4.9 + §5).\n' +
          '[manual] They will auto-evict after their individual `ttl` (10 min here).',
      );
    },
    45_000,
  );
});
