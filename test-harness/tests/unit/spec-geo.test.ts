/**
 * Unit tests for the BrightLink v1.1 geo + push spec helpers.
 *
 * Covers RFC §6.1 (BridgeIdentity kinds), §6.2 (PeerAttestation classes),
 * §6.3 (coordinate conversions), §7.1 (scope ladder), §8 (zone shape
 * algebra), §9.7 (error strings), §10 (LINK_PUSH AAD and event types).
 *
 * These tests pin the wire-level constants so any future change to a
 * value here is a wire-breaking change with a noisy test failure.
 */

import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';

import {
  // §7.1 scope ladder
  LINK_GEO_SCOPES,
  LINK_GEO_SCOPE_RANK,
  LINK_GEO_UNSIGNED_MAX_SCOPE,
  LINK_GEO_POLICIES,

  // §6.1 bridge identity
  LINK_BRIDGE_IDENTITY_KINDS,

  // §6.2 attestation classes
  LINK_ATTESTATION_CLASSES,

  // §8 zone shapes
  LINK_ZONE_SHAPE_TYPES,
  LINK_ZONE_DEFAULT_PRIORITY,

  // §6.3 coordinate conversion
  SPEED_OF_LIGHT_MPS,
  WGS84_A,
  WGS84_F,
  WGS84_E2,
  WGS84_B,
  wgs84ToEcef,
  ecefToWgs84,
  ecefToBrightSpace,
  brightSpaceToEcef,
  ecefChordDistance,

  // §10 LINK_PUSH
  LINK_PUSH_EVENTS,
  buildPushAad,

  // §9.7 / §10.5 errors
  LINK_GEO_ERRORS,
  LINK_PUSH_ERRORS,

  // shared with §4.6
  LINK_DIR_TAG,
  LINK_COMMANDS,
} from '../../src/spec/index.js';

// ────────────────────────────────────────────────────────────────────────────
// §7.1 scope ladder
// ────────────────────────────────────────────────────────────────────────────

describe('§7.1 LINK_GEO_SCOPES — wire-string ladder', () => {
  it('pins every scope string verbatim', () => {
    // These are persisted in `geo-acl.json`; changing one is wire-breaking.
    expect(LINK_GEO_SCOPES.STATUS).toBe('geo:status');
    expect(LINK_GEO_SCOPES.PROXIMITY).toBe('geo:proximity');
    expect(LINK_GEO_SCOPES.ZONE).toBe('geo:zone');
    expect(LINK_GEO_SCOPES.PRECISE).toBe('geo:precise');
    expect(LINK_GEO_SCOPES.TRAJECTORY).toBe('geo:trajectory');
  });

  it('rank order is strictly increasing', () => {
    expect(LINK_GEO_SCOPE_RANK[LINK_GEO_SCOPES.STATUS]).toBe(0);
    expect(LINK_GEO_SCOPE_RANK[LINK_GEO_SCOPES.PROXIMITY]).toBe(1);
    expect(LINK_GEO_SCOPE_RANK[LINK_GEO_SCOPES.ZONE]).toBe(2);
    expect(LINK_GEO_SCOPE_RANK[LINK_GEO_SCOPES.PRECISE]).toBe(3);
    expect(LINK_GEO_SCOPE_RANK[LINK_GEO_SCOPES.TRAJECTORY]).toBe(4);
  });

  it('caps unsigned binaries at geo:proximity', () => {
    // RFC §7.1: unsigned binaries CANNOT receive geo:zone or higher
    // regardless of any user grant. The cap is at proximity.
    expect(LINK_GEO_UNSIGNED_MAX_SCOPE).toBe(LINK_GEO_SCOPES.PROXIMITY);
    expect(LINK_GEO_SCOPE_RANK[LINK_GEO_UNSIGNED_MAX_SCOPE]).toBeLessThan(
      LINK_GEO_SCOPE_RANK[LINK_GEO_SCOPES.ZONE],
    );
  });

  it('policy values are exactly always/prompt/deny', () => {
    expect(LINK_GEO_POLICIES.ALWAYS).toBe('always');
    expect(LINK_GEO_POLICIES.PROMPT).toBe('prompt');
    expect(LINK_GEO_POLICIES.DENY).toBe('deny');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// §6.1 bridge identity kinds
// ────────────────────────────────────────────────────────────────────────────

describe('§6.1 LINK_BRIDGE_IDENTITY_KINDS', () => {
  it('exposes the three normative kinds', () => {
    expect(LINK_BRIDGE_IDENTITY_KINDS.SEP).toBe('SepBridgeIdentity');
    expect(LINK_BRIDGE_IDENTITY_KINDS.TPM2).toBe('Tpm2BridgeIdentity');
    expect(LINK_BRIDGE_IDENTITY_KINDS.FILE).toBe('FileBridgeIdentity');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// §6.2 peer attestation classes
// ────────────────────────────────────────────────────────────────────────────

describe('§6.2 LINK_ATTESTATION_CLASSES', () => {
  it('pins every class string verbatim', () => {
    // These are persisted in `geo-acl.json`; changing one breaks the ACL.
    expect(LINK_ATTESTATION_CLASSES.DEVELOPER_ID).toBe('DeveloperId');
    expect(LINK_ATTESTATION_CLASSES.MAC_APP_STORE).toBe('MacAppStore');
    expect(LINK_ATTESTATION_CLASSES.BSH_BUILTIN).toBe('BshBuiltin');
    expect(LINK_ATTESTATION_CLASSES.DPKG_SIGNED).toBe('DpkgSigned');
    expect(LINK_ATTESTATION_CLASSES.RPM_SIGNED).toBe('RpmSigned');
    expect(LINK_ATTESTATION_CLASSES.FLATPAK_SIGNED).toBe('FlatpakSigned');
    expect(LINK_ATTESTATION_CLASSES.UNSIGNED).toBe('Unsigned');
  });
});

// ────────────────────────────────────────────────────────────────────────────
// §8 zone shape algebra
// ────────────────────────────────────────────────────────────────────────────

describe('§8 LINK_ZONE_SHAPE_TYPES', () => {
  it('pins the four normative shape names', () => {
    expect(LINK_ZONE_SHAPE_TYPES.CIRCLE_2D).toBe('circle_2d');
    expect(LINK_ZONE_SHAPE_TYPES.CYLINDER_3D).toBe('cylinder_3d');
    expect(LINK_ZONE_SHAPE_TYPES.POLYGON_2D).toBe('polygon_2d');
    expect(LINK_ZONE_SHAPE_TYPES.BBOX_2D).toBe('bbox_2d');
  });

  it('default priorities reflect more-specific-wins', () => {
    // cylinder_3d (very specific) > circle_2d (specific) > polygon_2d
    // (medium) > bbox_2d (coarse). Most-specific-match-wins (§8) is
    // realised by these defaults.
    expect(LINK_ZONE_DEFAULT_PRIORITY.cylinder_3d).toBeGreaterThan(
      LINK_ZONE_DEFAULT_PRIORITY.circle_2d,
    );
    expect(LINK_ZONE_DEFAULT_PRIORITY.circle_2d).toBeGreaterThan(
      LINK_ZONE_DEFAULT_PRIORITY.polygon_2d,
    );
    expect(LINK_ZONE_DEFAULT_PRIORITY.polygon_2d).toBeGreaterThan(
      LINK_ZONE_DEFAULT_PRIORITY.bbox_2d,
    );
  });
});

// ────────────────────────────────────────────────────────────────────────────
// §6.3 coordinate conversions
// ────────────────────────────────────────────────────────────────────────────

describe('§6.3 WGS84 / ECEF / BrightSpace conversion', () => {
  it('pins the speed of light at exactly 299_792_458 m/s', () => {
    // This is the BrightSpace conversion factor; it is exact since the
    // 1983 SI metre redefinition. CRITICAL: changing this number is a
    // wire-breaking BrightSpace claim.
    expect(SPEED_OF_LIGHT_MPS).toBe(299_792_458);
  });

  it('pins WGS84 ellipsoid constants exactly', () => {
    expect(WGS84_A).toBe(6_378_137.0);
    expect(WGS84_F).toBeCloseTo(1 / 298.257223563, 15);
    expect(WGS84_E2).toBeCloseTo(2 * WGS84_F - WGS84_F * WGS84_F, 15);
    expect(WGS84_B).toBeCloseTo(WGS84_A * (1 - WGS84_F), 9);
  });

  it('round-trips a representative office-scale point through ECEF and back', () => {
    // Pike Place Market, Seattle. Picked because it's a pedestrian-zone
    // example you'd want to stand "in" using a circle_2d zone.
    const original = { lat: 47.6097, lon: -122.3422, alt_m: 17 };
    const ecef = wgs84ToEcef(original);
    const back = ecefToWgs84(ecef);
    expect(back.lat).toBeCloseTo(original.lat, 9);
    expect(back.lon).toBeCloseTo(original.lon, 9);
    expect(back.alt_m).toBeCloseTo(original.alt_m, 6);
  });

  it('matches the GODE reference station ECEF from BrightSpace §5 worked example', () => {
    // The BrightSpace standard's worked example pins:
    //   GODE @ ITRF2020 epoch 2015.0:
    //     X = +1,130,773.5956 m
    //     Y = -4,831,253.5718 m
    //     Z = +3,994,200.4453 m
    // The WGS84 approximation: lat 39.0218 N, lon -76.8266 E, alt ~14 m.
    // This test just confirms our conversion is consistent in both
    // directions to sub-metre precision around that point.
    const targetEcef = {
      x_m: 1_130_773.5956,
      y_m: -4_831_253.5718,
      z_m: 3_994_200.4453,
    };
    const wgs84 = ecefToWgs84(targetEcef);
    const back = wgs84ToEcef(wgs84);
    // Heikkinen + WGS84 forward should agree with the targets to <1 mm.
    expect(back.x_m).toBeCloseTo(targetEcef.x_m, 3);
    expect(back.y_m).toBeCloseTo(targetEcef.y_m, 3);
    expect(back.z_m).toBeCloseTo(targetEcef.z_m, 3);
    // Sanity: this is in Maryland, USA.
    expect(wgs84.lat).toBeGreaterThan(38);
    expect(wgs84.lat).toBeLessThan(40);
    expect(wgs84.lon).toBeLessThan(-76);
    expect(wgs84.lon).toBeGreaterThan(-78);
  });

  it('ECEF → BrightSpace divides every component by c, exact', () => {
    const ecef = { x_m: 1_130_773.5956, y_m: -4_831_253.5718, z_m: 3_994_200.4453 };
    const bs = ecefToBrightSpace(ecef, /* epoch_bd */ 9638.5);
    expect(bs.x_bm).toBe(ecef.x_m / SPEED_OF_LIGHT_MPS);
    expect(bs.y_bm).toBe(ecef.y_m / SPEED_OF_LIGHT_MPS);
    expect(bs.z_bm).toBe(ecef.z_m / SPEED_OF_LIGHT_MPS);
    expect(bs.epoch_bd).toBe(9638.5);
  });

  it('BrightSpace → ECEF round-trips ECEF → BrightSpace bit-exactly', () => {
    const ecef = { x_m: 1_130_773.5956, y_m: -4_831_253.5718, z_m: 3_994_200.4453 };
    const bs = ecefToBrightSpace(ecef, 9638.5);
    const back = brightSpaceToEcef(bs);
    // Bit-exact because /c then *c with c = exact integer is the same
    // floating-point round-trip in both directions.
    expect(back.x_m).toBe(ecef.x_m);
    expect(back.y_m).toBe(ecef.y_m);
    expect(back.z_m).toBe(ecef.z_m);
  });

  it('ecefChordDistance matches naive Euclidean distance', () => {
    // Two points ~1 km apart on the surface near Seattle.
    const a = wgs84ToEcef({ lat: 47.6062, lon: -122.3321, alt_m: 0 });
    const b = wgs84ToEcef({ lat: 47.6152, lon: -122.3321, alt_m: 0 }); // 1 km north
    const d = ecefChordDistance(a, b);
    // 0.009° latitude ≈ 1 km. Allow ±10 m for the chord-vs-arc difference
    // and floating-point.
    expect(d).toBeGreaterThan(990);
    expect(d).toBeLessThan(1010);
  });

  it('zero-distance check: a point is zero metres from itself', () => {
    const a = wgs84ToEcef({ lat: 47.6062, lon: -122.3321 });
    expect(ecefChordDistance(a, a)).toBe(0);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// §10 LINK_PUSH events and AAD construction
// ────────────────────────────────────────────────────────────────────────────

describe('§10 LINK_PUSH event surface', () => {
  it('pins the v1.1 event-name strings', () => {
    expect(LINK_PUSH_EVENTS.ZONE_TRANSITION).toBe('zone-transition');
    expect(LINK_PUSH_EVENTS.GEO_GRANT_CHANGED).toBe('geo-grant-changed');
  });

  describe('buildPushAad', () => {
    it('produces the §10.2 layout for a zone-transition event at counter 1', () => {
      const aad = buildPushAad({
        counter: 1n,
        event: 'zone-transition',
      });
      // Layout:
      //   LE32(1) ‖ 0x02
      //   LE32(8) ‖ u64_be(1)
      //   LE32(15) ‖ "zone-transition"
      //   LE32(0)
      // = 4+1+4+8+4+15+4 = 40 bytes.
      expect(aad.length).toBe(40);
      // First length-prefix is LE32(1).
      expect(aad.readUInt32LE(0)).toBe(1);
      // dir_tag is AGENT_TO_SHELL = 0x02.
      expect(aad[4]).toBe(LINK_DIR_TAG.AGENT_TO_SHELL);
      // counter length is LE32(8), counter is u64_be(1).
      expect(aad.readUInt32LE(5)).toBe(8);
      expect(aad.readBigUInt64BE(9)).toBe(1n);
      // event-name length is LE32(15), bytes are "zone-transition".
      expect(aad.readUInt32LE(17)).toBe(15);
      expect(aad.subarray(21, 36).toString('utf8')).toBe('zone-transition');
      // trailing context length-prefix is LE32(0) — empty context.
      expect(aad.readUInt32LE(36)).toBe(0);
    });

    it('different counter values produce different AAD bytes', () => {
      const a = buildPushAad({ counter: 1n, event: 'zone-transition' });
      const b = buildPushAad({ counter: 2n, event: 'zone-transition' });
      expect(a.equals(b)).toBe(false);
    });

    it('different event names produce different AAD bytes', () => {
      const a = buildPushAad({ counter: 1n, event: 'zone-transition' });
      const b = buildPushAad({ counter: 1n, event: 'geo-grant-changed' });
      expect(a.equals(b)).toBe(false);
    });

    it('rejects out-of-range u64 counters', () => {
      expect(() =>
        buildPushAad({ counter: -1n, event: 'zone-transition' }),
      ).toThrow(/counter out of u64 range/);
      expect(() =>
        buildPushAad({ counter: 0xffff_ffff_ffff_ffffn + 1n, event: 'x' }),
      ).toThrow(/counter out of u64 range/);
    });

    it('always uses dir_tag = AGENT_TO_SHELL (0x02)', () => {
      // Push frames are agent → shell by definition. The AAD byte at
      // offset 4 must always be 0x02.
      const aad = buildPushAad({ counter: 1n, event: 'zone-transition' });
      expect(aad[4]).toBe(0x02);
    });
  });
});

// ────────────────────────────────────────────────────────────────────────────
// §9.7 / §10.5 — error message strings
// ────────────────────────────────────────────────────────────────────────────

describe('§9.7 LINK_GEO_ERRORS — stable matchable strings', () => {
  // Clients SHOULD match on these literal strings, so the test pins them.
  it.each([
    ['SESSION_NOT_REGISTERED',     'geo: session not registered'],
    ['SCOPE_DENIED_BY_POLICY',     'geo: scope denied by policy'],
    ['SCOPE_UNAVAILABLE_UNSIGNED', 'geo: scope unavailable for unsigned binary'],
    ['PROMPT_TIMED_OUT',           'geo: user prompt timed out'],
    ['USER_DENIED',                'geo: user denied'],
    ['PROMPT_UNAVAILABLE',         'geo: prompt unavailable'],
    ['THROTTLED',                  'geo: throttled'],
    ['ENGINE_UNAVAILABLE',         'geo: engine unavailable'],
    ['ZONE_NOT_FOUND',             'geo: zone not found'],
    ['FORMAT_INVALID',             'geo: format invalid'],
    ['REFRESH_TIMED_OUT',          'geo: refresh timed out'],
  ])('%s = %s', (key, expected) => {
    expect(LINK_GEO_ERRORS[key as keyof typeof LINK_GEO_ERRORS]).toBe(expected);
  });
});

describe('§10.5 LINK_PUSH_ERRORS — stable matchable strings', () => {
  it.each([
    ['SESSION_NOT_REGISTERED', 'push: session not registered'],
    ['UNKNOWN_EVENT_TYPES',    'push: unknown event types'],
    ['SUBSCRIBE_LIMIT',        'push: subscribe limit'],
  ])('%s = %s', (key, expected) => {
    expect(LINK_PUSH_ERRORS[key as keyof typeof LINK_PUSH_ERRORS]).toBe(expected);
  });
});

// ────────────────────────────────────────────────────────────────────────────
// LINK_COMMANDS ordering — ensure the new geo names are present and stable
// ────────────────────────────────────────────────────────────────────────────

describe('LINK_COMMANDS includes the geo + push command surface', () => {
  it('exposes every v1.1 command verbatim', () => {
    expect(LINK_COMMANDS.REGISTER).toBe('LINK_REGISTER');
    expect(LINK_COMMANDS.DELIVER).toBe('LINK_DELIVER');
    expect(LINK_COMMANDS.GEO_STATUS).toBe('LINK_GEO_STATUS');
    expect(LINK_COMMANDS.GEO_PROXIMITY).toBe('LINK_GEO_PROXIMITY');
    expect(LINK_COMMANDS.GEO_ZONE).toBe('LINK_GEO_ZONE');
    expect(LINK_COMMANDS.GEO_GET).toBe('LINK_GEO_GET');
    expect(LINK_COMMANDS.GEO_REFRESH).toBe('LINK_GEO_REFRESH');
    expect(LINK_COMMANDS.PUSH).toBe('LINK_PUSH');
    expect(LINK_COMMANDS.AUDIT_EMIT).toBe('LINK_AUDIT_EMIT');
  });
});
