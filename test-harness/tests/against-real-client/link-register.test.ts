/**
 * `against-real-client` — drives the real production
 * `@digitaldefiance/enclave-bridge-client` against the spec-derived
 * `mock-brightnexus` in the same Node process.
 *
 * What this proves:
 *
 *   The production client's `linkRegister()` agrees with the spec-derived
 *   mock bridge at the byte level for every step of the §4.5 handshake:
 *   envelope construction, HKDF derivation, canonical transcript layout,
 *   and SEP signature verification.
 *
 * Why we test this way:
 *
 *   The mock bridge is the simplest possible from-scratch implementation
 *   of the spec — software P-256 SEP, no Apple frameworks, all crypto in
 *   userspace. If the production client interops with it, the production
 *   client matches the spec, not just the Swift implementation.
 *
 * Skip behavior: this suite never skips — both halves run in-process. If
 * the production-client `dist/` is missing or out of date, the import
 * fails clearly. Build the client first:
 *
 *   ( cd /Volumes/Code/bsh/enclave-bridge-client && yarn build )
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Buffer } from 'node:buffer';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { MockBrightNexus } from '../../src/mock-brightnexus/index.js';

// Production client — imported from its built ESM bundle. The harness has
// no Node-resolution path to its package name, so we reach into `dist/`
// directly via a relative path. This intentionally exercises the same
// entry-point a real consumer would use.
import {
  EnclaveBridgeClient,
  LINK_PROTOCOL_VERSION,
} from '../../../enclave-bridge-client/dist/index.js';

// ────────────────────────────────────────────────────────────────────────
// Per-test scaffold
// ────────────────────────────────────────────────────────────────────────

let mock: MockBrightNexus;
let client: EnclaveBridgeClient;
let tmpDir: string;
let socketPath: string;

beforeEach(async () => {
  mock = new MockBrightNexus();
  tmpDir = mkdtempSync(join(tmpdir(), 'against-real-client-'));
  socketPath = join(tmpDir, 'brightnexus.sock');
  await mock.start(socketPath);

  client = new EnclaveBridgeClient({
    socketPath,
    autoReconnect: false,
    cacheKeys: false,
    debug: false,
  });
  await client.connect();
});

afterEach(async () => {
  try {
    await client?.disconnect();
  } catch {
    // best effort
  }
  await mock?.stop();
  try {
    rmSync(tmpDir, { recursive: true, force: true });
  } catch {
    // best effort
  }
});

// ────────────────────────────────────────────────────────────────────────
// Sanity: production client speaks EBP/1 to mock-brightnexus
// ────────────────────────────────────────────────────────────────────────

describe('production client vs mock-brightnexus — EBP/1 sanity', () => {
  it('GET_PUBLIC_KEY returns 65-byte uncompressed', async () => {
    const pub = await client.getPublicKey();
    expect(pub.buffer.length).toBe(65);
    expect(pub.buffer[0]).toBe(0x04);
  });

  it('GET_ENCLAVE_PUBLIC_KEY returns 65-byte uncompressed', async () => {
    const pub = await client.getEnclavePublicKey();
    expect(pub.buffer.length).toBe(65);
    expect(pub.buffer[0]).toBe(0x04);
  });
});

// ────────────────────────────────────────────────────────────────────────
// LINK_REGISTER end-to-end
// ────────────────────────────────────────────────────────────────────────

describe('production client vs mock-brightnexus — LINK_REGISTER', () => {
  it('completes a happy-path registration and exposes the session', async () => {
    const session = await client.linkRegister({ ttlSeconds: 600 });

    expect(session.sessionId.length).toBe(16);
    expect(session.kSession.length).toBe(32);
    expect(session.ttlSeconds).toBe(600);
    expect(session.sepPublicKey.length).toBe(65);
    expect(session.expiresAtUnix).toBe(session.bridgeIssuedAtUnix + 600);

    // Client must have stored the session and pinned the SEP key.
    expect(client.linkSession).not.toBeNull();
    expect(client.linkSession?.sessionId.equals(session.sessionId)).toBe(true);
    expect(client.pinnedSepPublicKey).not.toBeNull();
    expect(client.pinnedSepPublicKey?.equals(session.sepPublicKey)).toBe(true);
  });

  it('caps requested TTL at the §4.1 8-hour ceiling', async () => {
    const session = await client.linkRegister({ ttlSeconds: 999_999_999 });
    expect(session.ttlSeconds).toBe(8 * 3600);
  });

  it('client-derived K_session is non-zero and the bridge accepts it as a registered session', async () => {
    const session = await client.linkRegister({ ttlSeconds: 60 });
    // Implicit cross-check: if the bridge's K_session derivation drifted
    // from the client's, the bridge would have refused to bind the session
    // to its connection state and the audit log would record a registration
    // failure. Walk the audit log to assert success.
    const audit = mock.state.auditLog.find(
      (e) => e.kind === 'session_init' && e.sessionIdHex === session.sessionId.toString('hex'),
    );
    expect(audit).toBeDefined();
    // K_session is non-trivial.
    expect(session.kSession.some((b) => b !== 0)).toBe(true);
  });

  it('refuses a second linkRegister() on the same client without unregister', async () => {
    await client.linkRegister();
    await expect(() => client.linkRegister()).rejects.toThrow(/Already registered/);
  });

  it('linkUnregister() clears the session and zeros the key material', async () => {
    const session = await client.linkRegister();
    const before = Buffer.from(session.kSession);
    expect(before.some((b) => b !== 0)).toBe(true);

    client.linkUnregister();
    expect(client.linkSession).toBeNull();
    // The session object is the same instance as `client.linkSession` was;
    // unregister wipes it in place.
    expect(session.kSession.every((b) => b === 0)).toBe(true);
  });

  it('detects a SEP-key TOFU mismatch on re-registration', async () => {
    // First registration pins the SEP key.
    await client.linkRegister();
    const pinned = client.pinnedSepPublicKey!;
    expect(pinned.length).toBe(65);

    // Force-flip a byte of the pin (simulating a swapped bridge identity).
    const tampered = Buffer.from(pinned);
    tampered[10] ^= 0x01;
    client.pinnedSepPublicKey = tampered;
    client.linkUnregister();

    await expect(() => client.linkRegister()).rejects.toThrow(/TOFU mismatch/);
  });

  it('LINK_PROTOCOL_VERSION constant is 1', () => {
    expect(LINK_PROTOCOL_VERSION).toBe(1);
  });
});
