/**
 * Wave 2 — end-to-end tests for the LINK_GEO_* command surface against
 * `mock-brightnexus`.
 *
 * Exercises:
 *   - LINK_GEO_STATUS bypasses the ACL.
 *   - LINK_GEO_PROXIMITY: yes/no for a named zone, prompt-gated.
 *   - LINK_GEO_ZONE: returns the most-specific zone match.
 *   - LINK_GEO_GET: dual-coordinate output (wgs84 / brightspace / both).
 *   - LINK_GEO_REFRESH: triggers a fresh fix.
 *   - Unsigned-binary cap (geo:zone+ rejected even with prompt allow).
 *   - ACL "always" entry skips the prompt.
 *   - Prompt timeout returns the right error string.
 *   - Push: subscribing to zone-transition produces an AAD-sealed frame
 *     when the zone changes (covered in mock-brightnexus.test.ts).
 *
 * Each test stands up a fresh mock + a fresh `MockBshClient` so state
 * doesn't leak between cases.
 */

import { Buffer } from 'node:buffer';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  describe,
  expect,
  it,
  beforeEach,
  afterEach,
} from 'vitest';

import {
  MockBrightNexus,
  MockPeerAttestationProvider,
  MockPromptCoordinator,
  FixedGeoSource,
  AWS_CLI_ATTESTATION,
  BSH_SHELL_ATTESTATION,
  DEFAULT_UNSIGNED_ATTESTATION,
  withSshSession,
  type ZoneDefinition,
  type LinkAclEntry,
} from '../../src/mock-brightnexus/index.js';
import { MockBshClient } from '../../src/mock-bsh-client/index.js';
import {
  LINK_ATTESTATION_CLASSES,
  LINK_GEO_POLICIES,
  LINK_GEO_SCOPES,
  LINK_ZONE_SHAPE_TYPES,
  LINK_PUSH_EVENTS,
} from '../../src/spec/index.js';

// ────────────────────────────────────────────────────────────────────────────
// Test scaffolding
// ────────────────────────────────────────────────────────────────────────────

let tmpDir: string;
let socketPath: string;
let mock: MockBrightNexus;
let client: MockBshClient;

const PIKE_PLACE = { lat: 47.6097, lon: -122.3422 };
const PROD_OFFICE_ZONE: ZoneDefinition = {
  id: 'zone-prod-office',
  displayName: 'Prod Office',
  shape: {
    type: LINK_ZONE_SHAPE_TYPES.CIRCLE_2D,
    center: { wgs84: { lat: PIKE_PLACE.lat, lon: PIKE_PLACE.lon } },
    radius_m: 200,
  },
};
const HOME_ZONE: ZoneDefinition = {
  id: 'zone-home',
  displayName: 'Home',
  shape: {
    type: LINK_ZONE_SHAPE_TYPES.CIRCLE_2D,
    center: { wgs84: { lat: 47.6500, lon: -122.3500 } },
    radius_m: 100,
  },
};

async function setUpWithBshAttestation(): Promise<{
  prompt: MockPromptCoordinator;
  attestation: MockPeerAttestationProvider;
}> {
  tmpDir = mkdtempSync(join(tmpdir(), 'mock-bn-geo-'));
  socketPath = join(tmpDir, 'bn.sock');

  const prompt = new MockPromptCoordinator();
  const attestation = new MockPeerAttestationProvider();
  attestation.setDefault(BSH_SHELL_ATTESTATION);

  const geoSource = new FixedGeoSource();
  geoSource.setFixFromWgs84({
    lat: PIKE_PLACE.lat,
    lon: PIKE_PLACE.lon,
    accuracy_m: 5,
  });

  mock = new MockBrightNexus({
    promptCoordinator: prompt,
    peerAttestation: attestation,
    geoSource,
    initialZones: [PROD_OFFICE_ZONE, HOME_ZONE],
    promptTimeoutSeconds: 5,
  });
  await mock.start(socketPath);

  client = new MockBshClient();
  await client.connect(socketPath);
  await client.register();

  return { prompt, attestation };
}

async function tearDown(): Promise<void> {
  if (client) await client.disconnect();
  if (mock) await mock.stop();
  if (tmpDir) {
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
}

// ────────────────────────────────────────────────────────────────────────────
// LINK_GEO_STATUS — bypasses the ACL
// ────────────────────────────────────────────────────────────────────────────

describe('LINK_GEO_STATUS bypasses the ACL', () => {
  let prompt: MockPromptCoordinator;
  beforeEach(async () => {
    ({ prompt } = await setUpWithBshAttestation());
    void prompt;
  });
  afterEach(async () => { await tearDown(); });

  it('returns alive=true when a fix is pinned, with no prompt fired', async () => {
    const r = await client.send({ cmd: 'LINK_GEO_STATUS' });
    expect(r['ok']).toBe(true);
    expect(r['alive']).toBe(true);
    expect(typeof r['accuracy_m']).toBe('number');
    expect(prompt.promptsFired().length).toBe(0);
  });

  it('returns alive=false and engine_kind=FixedGeoSource if no fix is pinned', async () => {
    // Clear the fix.
    (mock.state.geoSource as FixedGeoSource).clearFix();
    const r = await client.send({ cmd: 'LINK_GEO_STATUS' });
    expect(r['ok']).toBe(true);
    expect(r['alive']).toBe(false);
    expect(r['engine_kind']).toBe('FixedGeoSource');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// LINK_GEO_PROXIMITY — gated by geo:proximity
// ────────────────────────────────────────────────────────────────────────────

describe('LINK_GEO_PROXIMITY', () => {
  let prompt: MockPromptCoordinator;
  beforeEach(async () => {
    ({ prompt } = await setUpWithBshAttestation());
  });
  afterEach(async () => { await tearDown(); });

  it('user clicks Allow Once → returns in_zone=true for matching zone', async () => {
    prompt.pushAllowOnce();
    const r = await client.send({
      cmd: 'LINK_GEO_PROXIMITY',
      zone: 'zone-prod-office',
    });
    expect(r['ok']).toBe(true);
    expect(r['in_zone']).toBe(true);
    expect(typeof r['brightdate']).toBe('number');
  });

  it('user clicks Deny → error=geo: user denied', async () => {
    prompt.pushDeny();
    const r = await client.send({
      cmd: 'LINK_GEO_PROXIMITY',
      zone: 'zone-prod-office',
    });
    expect(r['error']).toBe('geo: user denied');
  });

  it('returns in_zone=false when the fix is outside the named zone', async () => {
    prompt.pushAllowOnce();
    const r = await client.send({
      cmd: 'LINK_GEO_PROXIMITY',
      zone: 'zone-home', // pinned fix is at Pike Place, not Home
    });
    expect(r['ok']).toBe(true);
    expect(r['in_zone']).toBe(false);
  });

  it('returns geo: zone not found for an undefined zone', async () => {
    prompt.pushAllowOnce();
    const r = await client.send({
      cmd: 'LINK_GEO_PROXIMITY',
      zone: 'zone-does-not-exist',
    });
    expect(r['error']).toBe('geo: zone not found');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// LINK_GEO_ZONE — gated by geo:zone
// ────────────────────────────────────────────────────────────────────────────

describe('LINK_GEO_ZONE', () => {
  let prompt: MockPromptCoordinator;
  beforeEach(async () => {
    ({ prompt } = await setUpWithBshAttestation());
  });
  afterEach(async () => { await tearDown(); });

  it('returns the most-specific zone for the current fix', async () => {
    prompt.pushAllowOnce();
    const r = await client.send({ cmd: 'LINK_GEO_ZONE' });
    expect(r['ok']).toBe(true);
    expect(r['zone']).toBe('zone-prod-office');
    expect(r['dwell_seconds']).toBe(0); // first observation
  });

  it('returns zone=null when the fix is in no defined zone', async () => {
    // Move the fix far away.
    (mock.state.geoSource as FixedGeoSource).setFixFromWgs84({
      lat: 0, lon: 0, accuracy_m: 5,
    });
    prompt.pushAllowOnce();
    const r = await client.send({ cmd: 'LINK_GEO_ZONE' });
    expect(r['ok']).toBe(true);
    expect(r['zone']).toBeNull();
  });
});

// ────────────────────────────────────────────────────────────────────────────
// LINK_GEO_GET — gated by geo:precise, dual-coordinate output
// ────────────────────────────────────────────────────────────────────────────

describe('LINK_GEO_GET', () => {
  let prompt: MockPromptCoordinator;
  beforeEach(async () => {
    ({ prompt } = await setUpWithBshAttestation());
  });
  afterEach(async () => { await tearDown(); });

  it('format=both returns wgs84 + brightspace coords', async () => {
    prompt.pushAllowOnce();
    const r = await client.send({ cmd: 'LINK_GEO_GET', format: 'both' });
    expect(r['ok']).toBe(true);
    const pos = r['position'] as Record<string, unknown>;
    expect(pos['wgs84']).toBeDefined();
    expect(pos['brightspace']).toBeDefined();
    const wgs = pos['wgs84'] as { lat: number; lon: number };
    expect(wgs.lat).toBeCloseTo(PIKE_PLACE.lat, 6);
    expect(wgs.lon).toBeCloseTo(PIKE_PLACE.lon, 6);
    const bs = pos['brightspace'] as {
      x_bm: number; y_bm: number; z_bm: number; epoch_bd: number;
    };
    // Sanity: BrightSpace coords are ECEF/c, on the order of 0.01 bm
    // (millibrights) for a point near Earth's surface.
    expect(Math.abs(bs.x_bm)).toBeGreaterThan(0);
    expect(Math.abs(bs.y_bm)).toBeGreaterThan(0);
    expect(Math.abs(bs.z_bm)).toBeGreaterThan(0);
    expect(typeof bs.epoch_bd).toBe('number');
  });

  it('format=wgs84 omits the brightspace sub-object', async () => {
    prompt.pushAllowOnce();
    const r = await client.send({ cmd: 'LINK_GEO_GET', format: 'wgs84' });
    expect(r['ok']).toBe(true);
    const pos = r['position'] as Record<string, unknown>;
    expect(pos['wgs84']).toBeDefined();
    expect(pos['brightspace']).toBeUndefined();
  });

  it('format=brightspace omits the wgs84 sub-object', async () => {
    prompt.pushAllowOnce();
    const r = await client.send({ cmd: 'LINK_GEO_GET', format: 'brightspace' });
    expect(r['ok']).toBe(true);
    const pos = r['position'] as Record<string, unknown>;
    expect(pos['wgs84']).toBeUndefined();
    expect(pos['brightspace']).toBeDefined();
  });

  it('rejects format=junk with geo: format invalid', async () => {
    const r = await client.send({ cmd: 'LINK_GEO_GET', format: 'junk' });
    expect(r['error']).toBe('geo: format invalid');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// Unsigned-binary cap (RFC §7.1)
// ────────────────────────────────────────────────────────────────────────────

describe('Unsigned-binary cap (RFC §7.1)', () => {
  beforeEach(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), 'mock-bn-geo-unsigned-'));
    socketPath = join(tmpDir, 'bn.sock');
    const prompt = new MockPromptCoordinator()
      .pushAllowAlways(); // would grant if asked
    const attestation = new MockPeerAttestationProvider();
    attestation.setDefault(DEFAULT_UNSIGNED_ATTESTATION);
    const geoSource = new FixedGeoSource();
    geoSource.setFixFromWgs84({ lat: PIKE_PLACE.lat, lon: PIKE_PLACE.lon });
    mock = new MockBrightNexus({
      promptCoordinator: prompt,
      peerAttestation: attestation,
      geoSource,
      initialZones: [PROD_OFFICE_ZONE],
    });
    await mock.start(socketPath);
    client = new MockBshClient();
    await client.connect(socketPath);
    await client.register();
  });
  afterEach(async () => { await tearDown(); });

  it('unsigned binary CANNOT receive geo:zone even with prompt allow_always', async () => {
    const r = await client.send({ cmd: 'LINK_GEO_ZONE' });
    expect(r['error']).toBe('geo: scope unavailable for unsigned binary');
  });

  it('unsigned binary CAN receive geo:proximity', async () => {
    const r = await client.send({
      cmd: 'LINK_GEO_PROXIMITY',
      zone: 'zone-prod-office',
    });
    // The prompt resolution proceeds — proximity is at-or-below the cap.
    expect(r['ok']).toBe(true);
  });

  it('unsigned binary CANNOT receive geo:precise even with prompt allow_always', async () => {
    const r = await client.send({ cmd: 'LINK_GEO_GET', format: 'both' });
    expect(r['error']).toBe('geo: scope unavailable for unsigned binary');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// ACL "always" entry skips the prompt
// ────────────────────────────────────────────────────────────────────────────

describe('ACL always-grant entries skip the prompt', () => {
  let prompt: MockPromptCoordinator;
  beforeEach(async () => {
    ({ prompt } = await setUpWithBshAttestation());

    // Pre-populate an ACL entry for bsh granting geo:zone always.
    const entry: LinkAclEntry = {
      id: 'test-entry-bsh',
      displayName: 'bsh shell (test)',
      attestationClass: BSH_SHELL_ATTESTATION.attestationClass,
      issuerId: BSH_SHELL_ATTESTATION.issuerId,
      subjectId: BSH_SHELL_ATTESTATION.subjectId,
      expectedPath: BSH_SHELL_ATTESTATION.executablePath,
      fallbackHash: null,
      scopes: {
        [LINK_GEO_SCOPES.STATUS]: LINK_GEO_POLICIES.PROMPT,
        [LINK_GEO_SCOPES.PROXIMITY]: LINK_GEO_POLICIES.PROMPT,
        [LINK_GEO_SCOPES.ZONE]: LINK_GEO_POLICIES.ALWAYS,
        [LINK_GEO_SCOPES.PRECISE]: LINK_GEO_POLICIES.PROMPT,
        [LINK_GEO_SCOPES.TRAJECTORY]: LINK_GEO_POLICIES.PROMPT,
      },
      addedAtBd: 9000,
      lastUsedBd: 9000,
      expiresAtBd: null,
    };
    mock.state.acl.upsert(entry);
  });
  afterEach(async () => { await tearDown(); });

  it('LINK_GEO_ZONE returns immediately without firing a prompt', async () => {
    const r = await client.send({ cmd: 'LINK_GEO_ZONE' });
    expect(r['ok']).toBe(true);
    expect(r['zone']).toBe('zone-prod-office');
    expect(prompt.promptsFired().length).toBe(0);
  });

  it('audit log records geo:allowed_by_acl with policyAtDecision=always', async () => {
    await client.send({ cmd: 'LINK_GEO_ZONE' });
    const audit = mock.state.auditLog.filter((e) =>
      e.kind.startsWith('geo:'),
    );
    expect(audit.length).toBeGreaterThan(0);
    const entry = audit[audit.length - 1];
    expect(entry.kind).toBe('geo:allowed_by_acl');
    expect(entry.payload.policyAtDecision).toBe('always');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// Prompt timeout
// ────────────────────────────────────────────────────────────────────────────

describe('Prompt timeout returns geo: user prompt timed out', () => {
  beforeEach(async () => {
    await setUpWithBshAttestation();
    // Default prompt coordinator returns timeout.
  });
  afterEach(async () => { await tearDown(); });

  it('returns geo: user prompt timed out', async () => {
    const r = await client.send({
      cmd: 'LINK_GEO_PROXIMITY',
      zone: 'zone-prod-office',
    });
    expect(r['error']).toBe('geo: user prompt timed out');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// SSH session — prompt fires with SSH source noted in the attestation
// ────────────────────────────────────────────────────────────────────────────

describe('SSH session attestation populates the prompt request', () => {
  let prompt: MockPromptCoordinator;
  beforeEach(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), 'mock-bn-geo-ssh-'));
    socketPath = join(tmpDir, 'bn.sock');
    prompt = new MockPromptCoordinator().pushAllowOnce();
    const attestation = new MockPeerAttestationProvider();
    attestation.setDefault(
      withSshSession(BSH_SHELL_ATTESTATION, {
        sourceUser: 'alice',
        sourceHost: 'laptop.local',
      }),
    );
    const geoSource = new FixedGeoSource();
    geoSource.setFixFromWgs84({ lat: PIKE_PLACE.lat, lon: PIKE_PLACE.lon });
    mock = new MockBrightNexus({
      promptCoordinator: prompt,
      peerAttestation: attestation,
      geoSource,
      initialZones: [PROD_OFFICE_ZONE],
    });
    await mock.start(socketPath);
    client = new MockBshClient();
    await client.connect(socketPath);
    await client.register();
  });
  afterEach(async () => { await tearDown(); });

  it('prompt request carries the ssh_session info', async () => {
    await client.send({
      cmd: 'LINK_GEO_PROXIMITY',
      zone: 'zone-prod-office',
    });
    const fired = prompt.promptsFired();
    expect(fired).toHaveLength(1);
    expect(fired[0].attestation.sshSession).not.toBeNull();
    expect(fired[0].attestation.sshSession?.sourceUser).toBe('alice');
    expect(fired[0].attestation.sshSession?.sourceHost).toBe('laptop.local');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// Zone transition push — covered separately in mock-brightnexus.test.ts but
// repeated here in a more focused form to validate the AAD payload decrypts.
// ────────────────────────────────────────────────────────────────────────────

describe('Zone transition push frame decrypts under the session key', () => {
  beforeEach(async () => {
    await setUpWithBshAttestation();
    // Pre-grant geo:zone always so subscribe doesn't hit a prompt.
    mock.state.acl.upsert({
      id: 'test-entry-bsh',
      displayName: 'bsh shell (test)',
      attestationClass: BSH_SHELL_ATTESTATION.attestationClass,
      issuerId: BSH_SHELL_ATTESTATION.issuerId,
      subjectId: BSH_SHELL_ATTESTATION.subjectId,
      expectedPath: BSH_SHELL_ATTESTATION.executablePath,
      fallbackHash: null,
      scopes: {
        [LINK_GEO_SCOPES.STATUS]: LINK_GEO_POLICIES.ALWAYS,
        [LINK_GEO_SCOPES.PROXIMITY]: LINK_GEO_POLICIES.ALWAYS,
        [LINK_GEO_SCOPES.ZONE]: LINK_GEO_POLICIES.ALWAYS,
        [LINK_GEO_SCOPES.PRECISE]: LINK_GEO_POLICIES.PROMPT,
        [LINK_GEO_SCOPES.TRAJECTORY]: LINK_GEO_POLICIES.PROMPT,
      },
      addedAtBd: 9000,
      lastUsedBd: 9000,
      expiresAtBd: null,
    });
  });
  afterEach(async () => { await tearDown(); });

  it('subscribe → zone change → push frame body decrypts to {from, to, at_bd}', async () => {
    const events: Array<{ counter: bigint; eventName: string; payload: Buffer }> = [];

    // Move out of any zone first so the initial zone is `null`. This needs
    // to happen BEFORE we subscribe, otherwise the first transition fires
    // before our subscription is established and we miss it.
    (mock.state.geoSource as FixedGeoSource).setFixFromWgs84({
      lat: 0, lon: 0, accuracy_m: 5,
    });
    mock.state.geo.forceEvaluateZone();

    await client.subscribePush({
      events: ['zone-transition'],
      onPayload: (e) => events.push(e),
    });

    // Now move into the zone — this transition (null → zone-prod-office)
    // fires after the subscription is in place, so the subscriber sees it.
    // Use Pike Place coords — that's where PROD_OFFICE_ZONE is centered.
    (mock.state.geoSource as FixedGeoSource).setFixFromWgs84({
      lat: PIKE_PLACE.lat, lon: PIKE_PLACE.lon, accuracy_m: 5,
    });
    mock.state.geo.forceEvaluateZone();
    // The geo source's setFix* notifies the engine which evaluates the
    // transition. Give the runloop a tick to deliver the frame.
    await new Promise((r) => setTimeout(r, 50));

    expect(events.length).toBeGreaterThanOrEqual(1);
    const last = events[events.length - 1];
    expect(last.eventName).toBe(LINK_PUSH_EVENTS.ZONE_TRANSITION);
    const body = JSON.parse(last.payload.toString('utf8')) as {
      from: string | null;
      to: string | null;
      at_bd: number;
    };
    expect(body.from).toBeNull();
    expect(body.to).toBe('zone-prod-office');
    expect(typeof body.at_bd).toBe('number');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// Allow-always persists into geo-acl.json for next time
// ────────────────────────────────────────────────────────────────────────────

describe('Allow Always persists across requests', () => {
  let prompt: MockPromptCoordinator;
  beforeEach(async () => {
    ({ prompt } = await setUpWithBshAttestation());
  });
  afterEach(async () => { await tearDown(); });

  it('first request prompts; second request goes straight through', async () => {
    prompt.pushAllowAlways();
    const first = await client.send({ cmd: 'LINK_GEO_ZONE' });
    expect(first['ok']).toBe(true);
    expect(prompt.promptsFired().length).toBe(1);

    // Second request should hit the persisted ACL entry, no prompt.
    const second = await client.send({ cmd: 'LINK_GEO_ZONE' });
    expect(second['ok']).toBe(true);
    expect(prompt.promptsFired().length).toBe(1); // unchanged
  });
});

// ────────────────────────────────────────────────────────────────────────────
// Sanity: AWS CLI attestation is a different identity from bsh
// ────────────────────────────────────────────────────────────────────────────

describe('Different signed identities are recognised separately', () => {
  let prompt: MockPromptCoordinator;
  beforeEach(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), 'mock-bn-geo-mixed-'));
    socketPath = join(tmpDir, 'bn.sock');
    prompt = new MockPromptCoordinator();
    const attestation = new MockPeerAttestationProvider();
    // Two attestations queued: bsh first (gets allow_always), then aws.
    attestation.push(BSH_SHELL_ATTESTATION);
    attestation.push(AWS_CLI_ATTESTATION);

    const geoSource = new FixedGeoSource();
    geoSource.setFixFromWgs84({ lat: PIKE_PLACE.lat, lon: PIKE_PLACE.lon });

    mock = new MockBrightNexus({
      promptCoordinator: prompt,
      peerAttestation: attestation,
      geoSource,
      initialZones: [PROD_OFFICE_ZONE],
    });
    await mock.start(socketPath);
  });
  afterEach(async () => { await tearDown(); });

  it('bsh allow_always does NOT grant aws geo:zone — separate prompts fire', async () => {
    prompt.pushAllowAlways(); // for bsh
    prompt.pushDeny();         // for aws

    // First connection: bsh.
    const c1 = new MockBshClient();
    await c1.connect(socketPath);
    await c1.register();
    const r1 = await c1.send({ cmd: 'LINK_GEO_ZONE' });
    expect(r1['ok']).toBe(true);
    await c1.disconnect();

    // Second connection: aws. Different attestation identity → different
    // prompt → user denies.
    const c2 = new MockBshClient();
    await c2.connect(socketPath);
    await c2.register();
    const r2 = await c2.send({ cmd: 'LINK_GEO_ZONE' });
    expect(r2['error']).toBe('geo: user denied');
    await c2.disconnect();

    expect(prompt.promptsFired().length).toBe(2);
    expect(prompt.promptsFired()[0].attestation.subjectId).toBe(
      'org.digitaldefiance.bsh',
    );
    expect(prompt.promptsFired()[1].attestation.subjectId).toBe(
      'com.amazon.awscli2',
    );
  });
});

// Cap 'unused import' — keep these symbol-references for future tests.
void LINK_ATTESTATION_CLASSES;
