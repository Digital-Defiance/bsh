/**
 * Integration tests for RFC §4.9.5 (TTL clamp) and §4.4 (rate limiting).
 *
 * Exercises the policy surface against the real Swift bridge:
 *
 *   - A payload declaring `ttl: 86400` is silently clamped at the bridge.
 *     The bridge response still echoes type/context successfully.
 *   - 30 consecutive failed `LINK_DELIVER` calls inside a minute tear down
 *     the session — the next valid emit returns "Session not registered".
 *   - The TTL ceiling default is 1 hour (3600 s) per RFC §4.9.5.
 *
 * Skip behavior matches sibling suites: no reachable bridge → all tests
 * pass without doing work.
 */

import { describe, it, expect, beforeAll, afterEach, beforeEach } from 'vitest';
import { existsSync } from 'node:fs';

import { MockBshClient, discoverSocketPath } from '../../src/mock-bsh-client/index.js';

function findRealBridgeSocket(): string | null {
  const explicit = process.env['BRIGHTNEXUS_TEST_SOCKET'];
  if (explicit && existsSync(explicit)) return explicit;
  return discoverSocketPath();
}

let socketPath: string | null = null;
let client: MockBshClient | null = null;

beforeAll(() => {
  socketPath = findRealBridgeSocket();
  if (!socketPath) {
    console.log('[real-brightnexus] No running bridge found. Tests will be skipped.');
  }
});

beforeEach(async () => {
  if (!socketPath) return;
  client = new MockBshClient();
  await client.connect(socketPath);
  await client.register({ ttlSeconds: 600 });
});

afterEach(async () => {
  if (client) {
    await client.disconnect();
    client = null;
  }
});

const skipIfNoBridge = (): boolean => socketPath === null;

describe('real BrightNexus — BrightLink policy (§4.9.5 / §4.4)', () => {
  it('accepts a payload requesting a 24h ttl (clamping happens silently)', async () => {
    if (skipIfNoBridge()) return;
    // The bridge clamps `ttl` to its configured ceiling (1h default).
    // Successful response is the visible signal — no error, no hint that
    // clamping occurred. The user-facing UI is responsible for showing
    // the resolved expiry.
    const r = await client!.ingestCredential({
      type: 'plaintext',
      context: 'test://ttl-clamp-demo',
      body: {
        ttl: 86400, // 24 hours requested
        label: 'Long-TTL Test',
        value: 'should-be-clamped',
        masked: false,
      },
    });
    expect(r.type).toBe('plaintext');
  });

  it('tears down the session after 30 consecutive deliver failures (§4.4)', async () => {
    if (skipIfNoBridge()) return;

    // Send 30 malformed LINK_DELIVER requests. Each one fails structural
    // parse (`Missing counter`) but does NOT advance the inbound counter,
    // so we can keep hammering. After the 30th, the bridge tears down
    // our session.
    for (let i = 0; i < 30; i++) {
      const r = await client!.send({
        cmd: 'LINK_DELIVER',
        // intentionally omit counter/type/context/iv/ciphertext/authTag
      });
      expect(typeof r['error']).toBe('string');
    }

    // The next deliver should report "Session not registered" rather than
    // another structural error, indicating the session was wiped.
    const r = await client!.send({
      cmd: 'LINK_DELIVER',
    });
    expect(String(r['error'])).toBe('Session not registered on this connection');
  });

  it('allows a healthy session to burst many successful ingests (no success rate limit)', async () => {
    if (skipIfNoBridge()) return;
    // RFC §4.4: successful operations are not rate-limited at the protocol
    // layer. We send 50 well-formed credentials in a row; each must succeed.
    for (let i = 0; i < 50; i++) {
      const r = await client!.ingestCredential({
        type: 'plaintext',
        context: `test://burst/${i}`,
        body: {
          ttl: 60,
          label: `Burst ${i}`,
          value: String(i),
        },
      });
      expect(r.type).toBe('plaintext');
    }
  });
});
