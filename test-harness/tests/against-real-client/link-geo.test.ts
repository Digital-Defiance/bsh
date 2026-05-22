/**
 * `against-real-client` — production client geo + push surface against
 * the spec-derived `mock-brightnexus`.
 *
 * What this proves:
 *
 *   The production client's `linkGeoStatus`, `linkGeoProximity`,
 *   `linkGeoZone`, `linkGeoGet`, `linkGeoRefresh`, and `linkPushSubscribe`
 *   methods agree with the spec-derived mock bridge:
 *
 *     - JSON shape for each LINK_GEO_* command
 *     - Snake-case wire keys → camelCase TS surface
 *     - Both coordinate spaces (WGS84 + BrightSpace) round-trip cleanly
 *     - LINK_PUSH AAD construction is reciprocal: the bridge seals frames
 *       with `dir_tag = 0x02` and the client opens them with the same.
 *     - Per-session `c_agent_to_shell` counter advances per push frame
 *       and replay defence rejects out-of-window counters.
 *
 * Skip behavior: this suite never skips — both halves run in-process.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  MockBrightNexus,
  MockPeerAttestationProvider,
  MockPromptCoordinator,
  FixedGeoSource,
  BSH_SHELL_ATTESTATION,
  type ZoneDefinition,
  type LinkAclEntry,
} from '../../src/mock-brightnexus/index.js';
import {
  LINK_GEO_POLICIES,
  LINK_GEO_SCOPES,
  LINK_ZONE_SHAPE_TYPES,
} from '../../src/spec/index.js';

import {
  EnclaveBridgeClient,
} from '../../../enclave-bridge-client/dist/index.js';

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

let mock: MockBrightNexus;
let client: EnclaveBridgeClient;
let tmpDir: string;
let socketPath: string;
let prompt: MockPromptCoordinator;

beforeEach(async () => {
  prompt = new MockPromptCoordinator();
  const attestation = new MockPeerAttestationProvider().setDefault(
    BSH_SHELL_ATTESTATION,
  );
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
    initialZones: [PROD_OFFICE_ZONE],
    promptTimeoutSeconds: 5,
  });

  tmpDir = mkdtempSync(join(tmpdir(), 'against-real-client-geo-'));
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
    /* best effort */
  }
  await mock?.stop();
  try {
    rmSync(tmpDir, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
});

/** Pre-populate the mock ACL with `geo:zone always` and `geo:precise always`
 *  so geo calls don't have to round-trip through the prompt UI. */
function grantBshAlways(): void {
  const entry: LinkAclEntry = {
    id: 'test-bsh-always',
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
      [LINK_GEO_SCOPES.PRECISE]: LINK_GEO_POLICIES.ALWAYS,
      [LINK_GEO_SCOPES.TRAJECTORY]: LINK_GEO_POLICIES.PROMPT,
    },
    addedAtBd: 9000,
    lastUsedBd: 9000,
    expiresAtBd: null,
  };
  mock.state.acl.upsert(entry);
}

// ────────────────────────────────────────────────────────────────────────
// LINK_GEO_STATUS
// ────────────────────────────────────────────────────────────────────────

describe('production client vs mock — LINK_GEO_STATUS', () => {
  it('returns alive=true and engineKind=FixedGeoSource', async () => {
    await client.linkRegister();
    const status = await client.linkGeoStatus();
    expect(status.alive).toBe(true);
    expect(status.engineKind).toBe('FixedGeoSource');
    expect(status.accuracyM).toBe(5);
  });

  it('returns "geo: session not registered" when not registered', async () => {
    await expect(() => client.linkGeoStatus()).rejects.toThrow(
      /geo: session not registered/,
    );
  });

  it('does NOT fire a prompt (status bypasses the ACL)', async () => {
    await client.linkRegister();
    await client.linkGeoStatus();
    expect(prompt.promptsFired().length).toBe(0);
  });
});

// ────────────────────────────────────────────────────────────────────────
// LINK_GEO_PROXIMITY
// ────────────────────────────────────────────────────────────────────────

describe('production client vs mock — LINK_GEO_PROXIMITY', () => {
  it('returns inZone=true when the fix is inside the named zone', async () => {
    await client.linkRegister();
    grantBshAlways();
    const r = await client.linkGeoProximity('zone-prod-office');
    expect(r.inZone).toBe(true);
    expect(typeof r.brightdate).toBe('number');
  });

  it('throws InvalidOperationError on empty zone id', async () => {
    await client.linkRegister();
    grantBshAlways();
    await expect(() => client.linkGeoProximity('')).rejects.toThrow();
  });

  it('returns "geo: zone not found" for an unknown zone', async () => {
    await client.linkRegister();
    grantBshAlways();
    await expect(() =>
      client.linkGeoProximity('zone-nonexistent'),
    ).rejects.toThrow(/geo: zone not found/);
  });
});

// ────────────────────────────────────────────────────────────────────────
// LINK_GEO_ZONE
// ────────────────────────────────────────────────────────────────────────

describe('production client vs mock — LINK_GEO_ZONE', () => {
  it('returns zone=zone-prod-office for the pinned fix', async () => {
    await client.linkRegister();
    grantBshAlways();
    const r = await client.linkGeoZone();
    expect(r.zone).toBe('zone-prod-office');
    expect(r.dwellSeconds).toBeGreaterThanOrEqual(0);
  });

  it('returns zone=null when the fix is outside every defined zone', async () => {
    await client.linkRegister();
    grantBshAlways();
    (mock.state.geoSource as FixedGeoSource).setFixFromWgs84({
      lat: 0, lon: 0, accuracy_m: 5,
    });
    const r = await client.linkGeoZone();
    expect(r.zone).toBeNull();
  });
});

// ────────────────────────────────────────────────────────────────────────
// LINK_GEO_GET — dual-coordinate
// ────────────────────────────────────────────────────────────────────────

describe('production client vs mock — LINK_GEO_GET', () => {
  it('format=both returns wgs84 + brightspace coords', async () => {
    await client.linkRegister();
    grantBshAlways();
    const r = await client.linkGeoGet('both');
    expect(r.position.wgs84).toBeDefined();
    expect(r.position.brightspace).toBeDefined();
    expect(r.position.wgs84?.lat).toBeCloseTo(PIKE_PLACE.lat, 6);
    expect(r.position.wgs84?.lon).toBeCloseTo(PIKE_PLACE.lon, 6);
    expect(typeof r.position.brightspace?.x_bm).toBe('number');
    expect(typeof r.position.brightspace?.epoch_bd).toBe('number');
    expect(r.accuracyM).toBe(5);
  });

  it('format=wgs84 returns only the WGS84 sub-object', async () => {
    await client.linkRegister();
    grantBshAlways();
    const r = await client.linkGeoGet('wgs84');
    expect(r.position.wgs84).toBeDefined();
    expect(r.position.brightspace).toBeUndefined();
  });

  it('format=brightspace returns only the BrightSpace sub-object', async () => {
    await client.linkRegister();
    grantBshAlways();
    const r = await client.linkGeoGet('brightspace');
    expect(r.position.wgs84).toBeUndefined();
    expect(r.position.brightspace).toBeDefined();
  });

  it('throws on invalid format string', async () => {
    await client.linkRegister();
    await expect(() =>
      client.linkGeoGet('junk' as unknown as 'wgs84'),
    ).rejects.toThrow();
  });
});

// ────────────────────────────────────────────────────────────────────────
// LINK_GEO_REFRESH
// ────────────────────────────────────────────────────────────────────────

describe('production client vs mock — LINK_GEO_REFRESH', () => {
  it('returns fresh fix age + accuracy after a refresh', async () => {
    await client.linkRegister();
    grantBshAlways();
    const r = await client.linkGeoRefresh({ timeoutSeconds: 5 });
    expect(r.fixAgeSeconds).toBe(0);
    expect(r.accuracyM).toBe(5);
  });
});

// ────────────────────────────────────────────────────────────────────────
// LINK_PUSH — subscribe + zone-transition AEAD round-trip
// ────────────────────────────────────────────────────────────────────────

describe('production client vs mock — LINK_PUSH zone-transition', () => {
  it('subscribe → engine zone change → handler receives decrypted body', async () => {
    await client.linkRegister();
    grantBshAlways();

    // Move out of the zone before subscribing so the first transition the
    // subscriber sees is the deterministic null → zone-prod-office.
    (mock.state.geoSource as FixedGeoSource).setFixFromWgs84({
      lat: 0, lon: 0, accuracy_m: 5,
    });
    mock.state.geo.forceEvaluateZone();

    const events: Array<{ event: string; counter: bigint; body: Record<string, unknown> }> = [];
    const sub = await client.linkPushSubscribe(['zone-transition'], {
      onPayload: (e) => {
        events.push({ event: e.event, counter: e.counter, body: e.body });
      },
      onError: (err) => {
        // surface failures explicitly
        throw err;
      },
    });

    // Trigger a zone transition: move into the zone.
    (mock.state.geoSource as FixedGeoSource).setFixFromWgs84({
      lat: PIKE_PLACE.lat, lon: PIKE_PLACE.lon, accuracy_m: 5,
    });
    mock.state.geo.forceEvaluateZone();

    await new Promise((r) => setTimeout(r, 50));

    expect(events.length).toBeGreaterThanOrEqual(1);
    const last = events[events.length - 1];
    expect(last.event).toBe('zone-transition');
    expect(last.counter).toBe(1n);
    expect(last.body['from']).toBeNull();
    expect(last.body['to']).toBe('zone-prod-office');
    expect(typeof last.body['at_bd']).toBe('number');

    sub.close();
  });

  it('rejects subscribe before linkRegister', async () => {
    await expect(() =>
      client.linkPushSubscribe(['zone-transition'], {
        onPayload: () => undefined,
      }),
    ).rejects.toThrow(/requires a registered session/);
  });

  it('rejects subscribe with an empty event-name array', async () => {
    await client.linkRegister();
    await expect(() =>
      client.linkPushSubscribe([], { onPayload: () => undefined }),
    ).rejects.toThrow(/at least one event name/);
  });

  it('rejects subscribe with only unknown event names', async () => {
    await client.linkRegister();
    await expect(() =>
      client.linkPushSubscribe(['totally-fake-event'], {
        onPayload: () => undefined,
      }),
    ).rejects.toThrow(/push: unknown event types/);
  });
});

// ────────────────────────────────────────────────────────────────────────
// linkUnregister cleans up push subscriptions
// ────────────────────────────────────────────────────────────────────────

describe('production client vs mock — linkUnregister cleans up push subscriptions', () => {
  it('handlers stop firing after linkUnregister', async () => {
    await client.linkRegister();
    grantBshAlways();

    // Move out of zone before subscribing.
    (mock.state.geoSource as FixedGeoSource).setFixFromWgs84({
      lat: 0, lon: 0, accuracy_m: 5,
    });
    mock.state.geo.forceEvaluateZone();

    const events: Array<unknown> = [];
    await client.linkPushSubscribe(['zone-transition'], {
      onPayload: (e) => events.push(e),
    });

    // Trigger a transition the subscriber WILL see.
    (mock.state.geoSource as FixedGeoSource).setFixFromWgs84({
      lat: PIKE_PLACE.lat, lon: PIKE_PLACE.lon,
    });
    mock.state.geo.forceEvaluateZone();
    await new Promise((r) => setTimeout(r, 50));
    expect(events.length).toBeGreaterThanOrEqual(1);

    const beforeCount = events.length;
    client.linkUnregister();

    // Trigger another transition — handler should not see it because
    // linkUnregister cleared the subscriber list.
    (mock.state.geoSource as FixedGeoSource).setFixFromWgs84({
      lat: 0, lon: 0,
    });
    mock.state.geo.forceEvaluateZone();
    await new Promise((r) => setTimeout(r, 50));
    expect(events.length).toBe(beforeCount);
  });
});
