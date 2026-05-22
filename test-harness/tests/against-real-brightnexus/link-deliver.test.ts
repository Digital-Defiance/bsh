/**
 * Real-BrightNexus integration tests for `LINK_DELIVER` (RFC §4.9, BrightLink v1).
 *
 * Drives the running BrightNexus.app via `mock-bsh-client.ingestCredential()`.
 * Each test:
 *
 *   1. Opens an EBP/1 connection and registers a BrightLink session.
 *   2. Encrypts a credential body under K_session with AES-256-GCM and
 *      length-prefixed AAD (RFC §4.6.2).
 *   3. Sends it as a `LINK_DELIVER` JSON request.
 *   4. Asserts the bridge accepts and echoes back `type` / `context`.
 *
 * This validates:
 *
 *   - The mock-bsh-client AAD construction matches the harness spec
 *     byte-for-byte.
 *   - `BrightLinkPayload.decode` correctly extracts the inner type/context
 *     overrides.
 *   - The replay-window enforcement rejects re-emitted requests.
 *   - The bridge tolerates ASCII context strings of varying length.
 *
 * Skip behavior matches the sibling `link-register.test.ts`: no reachable
 * bridge → tests print a clear message and pass without doing work.
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
    console.log(
      '[real-brightnexus] No running bridge found. Tests will be skipped.\n' +
        '                  To run: launch BrightNexus.app and re-run.',
    );
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

// ────────────────────────────────────────────────────────────────────
// Happy path
// ────────────────────────────────────────────────────────────────────

describe('real BrightNexus LINK_DELIVER', () => {
  it('accepts an ephemeral-auth credential and echoes type/context', async () => {
    if (skipIfNoBridge()) return;
    const r = await client!.ingestCredential({
      type: 'ephemeral-auth',
      context: 'http://localhost:3005',
      body: {
        ttl: 60,
        issued_at: Math.floor(Date.now() / 1000),
        username: 'alice',
        password: 'p@ssw0rd',
      },
    });
    expect(r.type).toBe('ephemeral-auth');
    expect(r.context).toBe('http://localhost:3005');
  });

  it('accepts a db-connection credential', async () => {
    if (skipIfNoBridge()) return;
    const r = await client!.ingestCredential({
      type: 'db-connection',
      context: 'postgres://prod-db',
      body: {
        ttl: 30,
        engine: 'postgres',
        host: 'prod-db.internal',
        port: 5432,
        user: 'service',
        pass: 'secret-sauce',
      },
    });
    expect(r.type).toBe('db-connection');
    expect(r.context).toBe('postgres://prod-db');
  });

  it('respects body-side type/context overrides over the OSC plaintext fields', async () => {
    if (skipIfNoBridge()) return;
    // RFC §4.6 nota bene: body-supplied `type` wins. We send a generic
    // `link-payload` on the wire and the real type inside the body.
    const r = await client!.ingestCredential({
      type: 'link-payload',
      context: 'opaque',
      body: {
        type: 'ephemeral-auth',
        context: 'http://confidential.internal',
        ttl: 60,
        username: 'u',
        password: 'p',
      },
    });
    expect(r.type).toBe('ephemeral-auth');
    expect(r.context).toBe('http://confidential.internal');
  });

  // RFC §5.4–5.10: each new payload type round-trips through the bridge.
  // The bridge accepts any well-formed JSON body; type-specific rendering
  // is the menu-bar's job. These tests just confirm the bridge doesn't
  // reject the new schemas.
  it('accepts an api-token credential', async () => {
    if (skipIfNoBridge()) return;
    const r = await client!.ingestCredential({
      type: 'api-token',
      context: 'https://api.github.com',
      body: {
        ttl: 3600,
        token: 'ghp_x9kP4mQ2RtY8nL3vB7wZ-FAKE',
        header_name: 'Authorization',
        prefix: 'Bearer ',
        scopes: ['repo:read', 'actions:write'],
      },
    });
    expect(r.type).toBe('api-token');
  });

  it('accepts a cloud-session credential', async () => {
    if (skipIfNoBridge()) return;
    const r = await client!.ingestCredential({
      type: 'cloud-session',
      context: 'aws://account-1234567890/role/Developer',
      body: {
        ttl: 3600,
        provider: 'aws',
        access_key_id: 'ASIA-EXAMPLE-FAKE',
        secret_access_key: 'wJalrX-EXAMPLE-FAKE',
        session_token: 'FwoGZXIvYXdz-EXAMPLE-FAKE',
        region: 'us-west-2',
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      },
    });
    expect(r.type).toBe('cloud-session');
  });

  it('accepts a kubeconfig-context credential', async () => {
    if (skipIfNoBridge()) return;
    const r = await client!.ingestCredential({
      type: 'kubeconfig-context',
      context: 'k8s://prod-eu-west-1/orders',
      body: {
        ttl: 1800,
        server: 'https://k8s-prod-eu-west-1.example.com',
        cluster_name: 'prod-eu-west-1',
        namespace: 'orders',
        user: 'alice',
        token: 'eyJhbGciOiJSUzI1NiIs-EXAMPLE-FAKE',
        ca_pem: '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n',
      },
    });
    expect(r.type).toBe('kubeconfig-context');
  });

  it('accepts a totp-seed credential', async () => {
    if (skipIfNoBridge()) return;
    const r = await client!.ingestCredential({
      type: 'totp-seed',
      context: 'github.com:alice@example.com',
      body: {
        ttl: 86400,
        account: 'alice@example.com',
        issuer: 'GitHub',
        secret_base32: 'JBSWY3DPEHPK3PXP',
        period: 30,
        digits: 6,
        algorithm: 'SHA1',
      },
    });
    expect(r.type).toBe('totp-seed');
  });

  it('accepts a plaintext credential (visible)', async () => {
    if (skipIfNoBridge()) return;
    const r = await client!.ingestCredential({
      type: 'plaintext',
      context: 'github.com/account/recovery-codes',
      body: {
        ttl: 600,
        label: 'Backup MFA Code',
        value: '8472-9301-1538-2294',
        masked: false,
        kind: 'code',
      },
    });
    expect(r.type).toBe('plaintext');
  });

  it('accepts a plaintext credential (masked)', async () => {
    if (skipIfNoBridge()) return;
    const r = await client!.ingestCredential({
      type: 'plaintext',
      context: 'one-off-secret',
      body: {
        ttl: 60,
        label: 'OTP',
        value: '123456',
        masked: true,
      },
    });
    expect(r.type).toBe('plaintext');
  });
});


// ────────────────────────────────────────────────────────────────────
// Failure modes
// ────────────────────────────────────────────────────────────────────

describe('real BrightNexus LINK_DELIVER — error surface', () => {
  it('rejects a malformed deliver request with a clear error', async () => {
    if (skipIfNoBridge()) return;
    const r = await client!.send({
      cmd: 'LINK_DELIVER',
      // No counter, no type, no iv, no ciphertext, no authTag.
    });
    expect(typeof r['error']).toBe('string');
    // The bridge complains about the first missing field it notices.
    expect(String(r['error'])).toMatch(/Missing/);
  });

  it('rejects a LINK_DELIVER sent before LINK_REGISTER', async () => {
    if (skipIfNoBridge()) return;

    // Open a fresh connection that has NOT registered.
    const fresh = new MockBshClient();
    await fresh.connect(socketPath!);
    try {
      const r = await fresh.send({
        cmd: 'LINK_DELIVER',
        counter: 1,
        type: 'plaintext',
        context: 'test://x',
        iv: Buffer.alloc(12).toString('base64'),
        ciphertext: 'AAAA',
        authTag: Buffer.alloc(16).toString('base64'),
      });
      expect(r['error']).toBe('Session not registered on this connection');
    } finally {
      await fresh.disconnect();
    }
  });

  it('rejects a replayed sequence (same counter twice)', async () => {
    if (skipIfNoBridge()) return;
    // BrightLink v1: the bridge's replay defense rejects a re-submit at
    // counter ≤ lastAcceptedCounter. Build a deliver request manually
    // (not via ingestCredential, which auto-increments), send it twice.
    // The first one is accepted; the second is rejected.

    // First, do one normal ingest to establish counter = 1.
    await client!.ingestCredential({
      type: 'plaintext',
      context: 'test://replay-warmup',
      body: { value: 'warmup', ttl: 60 },
    });
    // Capture the session state via a re-read of `client.session`.
    const session = (client as unknown as { session: { outboundCounter: bigint } }).session;
    expect(session).toBeDefined();

    // Replay test: re-emit the exact same packet `ingestCredential` would
    // have built for counter = 1. We grab counter = 1 again by hand-crafting
    // a request with that value. The bridge will see counter <= last and reject.
    const stale = await client!.send({
      cmd: 'LINK_DELIVER',
      counter: 1,
      type: 'plaintext',
      context: 'test://replay',
      iv: Buffer.alloc(12, 0xaa).toString('base64'),
      ciphertext: 'AAAAAA==',
      authTag: Buffer.alloc(16, 0xbb).toString('base64'),
    });
    expect(String(stale['error'])).toMatch(/Counter replayed/);
  });

  it('rejects a LINK_DELIVER whose ciphertext fails AES-GCM auth', async () => {
    if (skipIfNoBridge()) return;
    // Cross-session attacks now fail at AES-GCM auth rather than at a
    // sessionId-prefix check (sessions are connection-bound on the wire,
    // so the attacker can't address the wrong session anymore — but
    // submitting forged ciphertext should still fail tag verification).
    const session = (client as unknown as { session: { outboundCounter: bigint } }).session;
    const r = await client!.send({
      cmd: 'LINK_DELIVER',
      counter: Number(session.outboundCounter + 1n),
      type: 'ephemeral-auth',
      context: 'http://forged.test',
      iv: Buffer.alloc(12, 0x11).toString('base64'),
      ciphertext: Buffer.alloc(40, 0x22).toString('base64'),
      authTag: Buffer.alloc(16, 0x33).toString('base64'),
    });
    expect(String(r['error'])).toBe('AES-GCM authentication failed');
  });
});
