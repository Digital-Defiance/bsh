/**
 * `GeoSource` interface and a `FixedGeoSource` test implementation.
 *
 * The real bridge uses platform-pluggable geo sources (RFC §6.3):
 *
 *   - `CoreLocationGeoSource` on macOS — wraps `CLLocationManager`.
 *   - `GeoClueGeoSource` on Linux — wraps GeoClue 2.5+ over D-Bus.
 *
 * The mock exposes a `FixedGeoSource` that returns whatever fix the test
 * pinned. Conversion between WGS84, ECEF metres, and BrightSpace is
 * delegated to the spec helpers (§6.3 of the RFC) so the mock and the real
 * bridge agree byte-for-byte on derived coordinates.
 */

import {
  ecefToBrightSpace,
  ecefToWgs84,
  wgs84ToEcef,
  type Wgs84Point,
  type EcefPoint,
  type BrightSpacePoint,
} from '../spec/index.js';

/** A single geographic fix from the platform's geo source. RFC §6.3. */
export interface GeoFix {
  /** BrightDate at which the fix was sampled. */
  brightdate: number;
  /** WGS84 components. Always populated. */
  wgs84: Wgs84Point;
  /** ITRF2020 ECEF metres. Always populated. */
  ecef: EcefPoint;
  /** 1-σ horizontal accuracy in metres. */
  accuracy_m: number;
  /** ECEF velocity in m/s if known (rare; null in most platforms). */
  velocity_mps: { vx_m: number; vy_m: number; vz_m: number } | null;
}

/** Status returned by `GeoSource.status()`. */
export interface GeoSourceStatus {
  /** Implementation kind (e.g. "CoreLocationGeoSource", "FixedGeoSource"). */
  kind: string;
  /** True if the engine has a usable fix. */
  alive: boolean;
  /** Age of the latest fix in seconds. null if no fix yet. */
  fix_age_seconds: number | null;
  /** Accuracy of the latest fix in metres. null if no fix yet. */
  accuracy_m: number | null;
}

/** Errors a geo source can return through `requestRefresh`. */
export type GeoError =
  | { kind: 'unavailable'; reason: string }
  | { kind: 'timeout' }
  | { kind: 'denied'; reason: string };

/** The platform-pluggable geo source. */
export interface GeoSource {
  /** Most recent fix or null if none has been obtained. */
  currentFix(): GeoFix | null;

  /** Trigger a fresh fix; resolves when the fix lands or rejects on
   *  timeout / unavailability. */
  requestRefresh(timeoutMs: number): Promise<GeoFix>;

  /** Subscribe to fix updates. Caller is invoked with each new fix as long
   *  as the subscription handle is alive. Returns a function that cancels
   *  the subscription. */
  subscribe(handler: (fix: GeoFix) => void): () => void;

  /** Status of the underlying engine. */
  status(): GeoSourceStatus;
}

/** A fully-deterministic geo source for tests.
 *
 * - Returns the configured fix from `currentFix()` once `setFix()` has
 *   been called.
 * - `requestRefresh()` resolves with the current fix immediately, or
 *   rejects with `unavailable` if no fix is pinned.
 * - Subscribers receive a notification on every `setFix()` call.
 *
 * The fix is timestamped with the bridge's clock at `setFix()` time, but
 * tests can override by passing `brightdate` to `setFix()`. */
export class FixedGeoSource implements GeoSource {
  private fix: GeoFix | null = null;
  private subscribers: Array<(fix: GeoFix) => void> = [];
  private nowUnix: () => number;

  constructor(args: { nowUnix?: () => number } = {}) {
    this.nowUnix = args.nowUnix ?? (() => Math.floor(Date.now() / 1000));
  }

  /** Convenience: pin a fix from a (lat, lon, alt) triple. The ECEF and
   *  BrightSpace forms are derived through the spec helpers. */
  setFixFromWgs84(args: {
    lat: number;
    lon: number;
    alt_m?: number;
    accuracy_m?: number;
    brightdate?: number;
  }): void {
    const wgs84: Wgs84Point = {
      lat: args.lat,
      lon: args.lon,
      alt_m: args.alt_m ?? 0,
    };
    const ecef = wgs84ToEcef(wgs84);
    const brightdate = args.brightdate ?? unixToBrightDate(this.nowUnix());
    this.fix = {
      brightdate,
      wgs84,
      ecef,
      accuracy_m: args.accuracy_m ?? 10,
      velocity_mps: null,
    };
    this.notify();
  }

  /** Pin a fix from raw ECEF metres. WGS84 is derived. */
  setFixFromEcef(args: {
    x_m: number;
    y_m: number;
    z_m: number;
    accuracy_m?: number;
    brightdate?: number;
  }): void {
    const ecef: EcefPoint = { x_m: args.x_m, y_m: args.y_m, z_m: args.z_m };
    const wgs84 = ecefToWgs84(ecef);
    const brightdate = args.brightdate ?? unixToBrightDate(this.nowUnix());
    this.fix = {
      brightdate,
      wgs84,
      ecef,
      accuracy_m: args.accuracy_m ?? 10,
      velocity_mps: null,
    };
    this.notify();
  }

  /** Clear the pinned fix. After this `currentFix()` returns null. */
  clearFix(): void {
    this.fix = null;
  }

  currentFix(): GeoFix | null {
    return this.fix;
  }

  async requestRefresh(_timeoutMs: number): Promise<GeoFix> {
    if (this.fix === null) {
      throw new Error('FixedGeoSource has no fix pinned');
    }
    return this.fix;
  }

  subscribe(handler: (fix: GeoFix) => void): () => void {
    this.subscribers.push(handler);
    return () => {
      this.subscribers = this.subscribers.filter((s) => s !== handler);
    };
  }

  status(): GeoSourceStatus {
    if (this.fix === null) {
      return {
        kind: 'FixedGeoSource',
        alive: false,
        fix_age_seconds: null,
        accuracy_m: null,
      };
    }
    return {
      kind: 'FixedGeoSource',
      alive: true,
      fix_age_seconds: Math.max(
        0,
        this.nowUnix() - brightDateToUnix(this.fix.brightdate),
      ),
      accuracy_m: this.fix.accuracy_m,
    };
  }

  private notify(): void {
    if (this.fix === null) return;
    for (const handler of this.subscribers) {
      try {
        handler(this.fix);
      } catch {
        // Never let a misbehaving subscriber kill another. The real
        // engine has the same property.
      }
    }
  }
}

/** Convenience helper exposed for tests. */
export function projectFix(
  fix: GeoFix,
): { wgs84: Wgs84Point; ecef: EcefPoint; brightspace: BrightSpacePoint } {
  return {
    wgs84: fix.wgs84,
    ecef: fix.ecef,
    brightspace: ecefToBrightSpace(fix.ecef, fix.brightdate),
  };
}

// ────────────────────────────────────────────────────────────────────────────
// BrightDate ↔ Unix helpers (J2000.0 = Unix ms 946_727_935_816, per the
// BrightDate specification).
// ────────────────────────────────────────────────────────────────────────────

const J2000_UTC_UNIX_MS = 946_727_935_816;
const SECONDS_PER_DAY = 86_400;

function unixToBrightDate(unixSeconds: number): number {
  return (unixSeconds * 1000 - J2000_UTC_UNIX_MS) / 1000 / SECONDS_PER_DAY;
}

function brightDateToUnix(bd: number): number {
  return Math.round((bd * SECONDS_PER_DAY * 1000 + J2000_UTC_UNIX_MS) / 1000);
}
