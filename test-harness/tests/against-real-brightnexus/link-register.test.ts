/**
 * Real-BrightNexus integration tests for LINK_REGISTER.
 *
 * Drives a running BrightNexus.app instance with `mock-bsh-client`. The tests
 * assert that the real Swift implementation produces output the spec-derived
 * mock client recognizes — same K_session derivation, same transcript layout,
 * same SEP signature path.
 *
 * Preconditions:
 *   - BrightNexus.app must be running (Xcode → ⌘R, or open the built .app
 *     from /Applications).
 *   - The bridge must be listening at one of the discovery paths
 *     (typically ~/.brightchain/brightnexus/brightnexus.sock) or at a path
 *     specified via the BRIGHTNEXUS_TEST_SOCKET env var.
 *
 * Skip behavior:
 *   - If no reachable socket is found, the tests print a clear message and
 *     skip rather than fail. CI runners that don't have BrightNexus available
 *     get a green run; macOS dev boxes with the app running run the tests.
 *
 * To force a specific socket path:
 *   BRIGHTNEXUS_TEST_SOCKET=/tmp/whatever yarn test:against-real-brightnexus
 */

import { describe, it, expect, beforeAll, afterEach, beforeEach } from 'vitest';
import { Buffer } from 'node:buffer';
import { existsSync } from 'node:fs';

import { MockBshClient, discoverSocketPath } from '../../src/mock-bsh-client/index.js';
import {
  EBP1_COMMANDS,
  BRIGHTNEXUS_APP_NAME,
  LINK_PROTOCOL_VERSION,
  LINK_MAX_TTL_SECONDS,
} from '../../src/spec/index.js';

// ────────────────────────────────────────────────────────────────────
// Discovery + skip logic
// ────────────────────────────────────────────────────────────────────

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
    console.log(
      '[real-brightnexus] No running bridge found. Tests will be skipped.\n' +
        '                  To run: launch BrightNexus.app and re-run.\n' +
        '                  Or:     BRIGHTNEXUS_TEST_SOCKET=/path yarn test:against-real-brightnexus',
    );
  } else {
    console.log(`[real-brightnexus] Driving against ${socketPath}`);
  }
});

beforeEach(async () => {
  if (!socketPath) return;
  client = new MockBshClient();
  await client.connect(socketPath);
});

afterEach(async () => {
  if (client) {
    await client.disconnect();
    client = null;
  }
});

const skipIfNoBridge = (): boolean => socketPath === null;

// ────────────────────────────────────────────────────────────────────
// EBP/1 sanity (proves we're talking to a BrightLink-aware BrightNexus,
// not a stale Enclave Bridge or some other EBP/1 service)
// ────────────────────────────────────────────────────────────────────

describe('real BrightNexus EBP/1 surface', () => {
  it('VERSION reports app=brightnexus and brightlinkProtocolVersion=1', async () => {
    if (skipIfNoBridge()) return;
    const r = await client!.send({ cmd: EBP1_COMMANDS.VERSION });
    expect(r['app']).toBe(BRIGHTNEXUS_APP_NAME);
    expect(r['brightlinkProtocolVersion']).toBe(LINK_PROTOCOL_VERSION);
  });

  it('GET_PUBLIC_KEY returns 65-byte uncompressed', async () => {
    if (skipIfNoBridge()) return;
    const pub = await client!.getPublicKey();
    expect(pub.length).toBe(65);
    expect(pub[0]).toBe(0x04);
  });

  it('GET_ENCLAVE_PUBLIC_KEY returns 65-byte uncompressed (real Apple SEP)', async () => {
    if (skipIfNoBridge()) return;
    const pub = await client!.getEnclavePublicKey();
    expect(pub.length).toBe(65);
    expect(pub[0]).toBe(0x04);
  });
});

// ────────────────────────────────────────────────────────────────────
// LINK_REGISTER end-to-end against real Apple SEP
// ────────────────────────────────────────────────────────────────────

describe('real BrightNexus LINK_REGISTER', () => {
  it('completes a happy-path registration with Apple-SEP-signed transcript', async () => {
    if (skipIfNoBridge()) return;

    // The mock client does the full §4.5 flow — including verifying the
    // bridge's SEP-signed transcript. If that signature verification passes,
    // the real Swift implementation matches the spec-derived layout.
    const session = await client!.register({ ttlSeconds: 600 });
    expect(session.sessionId.length).toBe(16);
    expect(session.kSession.length).toBe(32);
    expect(session.ttlSeconds).toBe(600);
    expect(session.sepPublicKey.length).toBe(65);
  });

  it('caps TTL at 8 hours', async () => {
    if (skipIfNoBridge()) return;
    const session = await client!.register({ ttlSeconds: 99_999_999 });
    expect(session.ttlSeconds).toBe(LINK_MAX_TTL_SECONDS);
  });

  it('rejects an envelope addressed to the wrong key', async () => {
    if (skipIfNoBridge()) return;

    // Send an arbitrary base64 blob as `envelope`. The real bridge should
    // fail decryption and return "Decryption failed".
    const r = await client!.send({
      cmd: 'LINK_REGISTER',
      protocolVersion: 1,
      clientNonce: Buffer.alloc(16, 0xab).toString('base64'),
      envelope: Buffer.alloc(120, 0x00).toString('base64'),
    });
    expect(r['error']).toBe('Decryption failed');
  });

  it('rejects an unsupported protocol version', async () => {
    if (skipIfNoBridge()) return;
    const r = await client!.send({
      cmd: 'LINK_REGISTER',
      protocolVersion: 2,
      clientNonce: Buffer.alloc(16, 0xab).toString('base64'),
      envelope: Buffer.alloc(120, 0x00).toString('base64'),
    });
    expect(r['error']).toBe('Unsupported BrightLink protocol version');
  });

  it('two consecutive registrations on the same connection both succeed', async () => {
    if (skipIfNoBridge()) return;
    // First registration on this connection.
    const a = await client!.register();

    // Second registration: the mock-bsh-client refuses (its own policy) when
    // it already has a session, so we drop the in-process session record and
    // re-call. The real bridge should accept and mint a new session.
    client!.session = null;
    const b = await client!.register();

    // Different session ids; bridge wiped the prior session per RFC §4.3.
    expect(a.sessionId.equals(b.sessionId)).toBe(false);
  });
});
