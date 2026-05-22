/**
 * Zone engine: point-in-shape evaluation for the four normative zone
 * shapes from RFC §8.
 *
 * Shape semantics:
 *   circle_2d   — Euclidean ECEF chord distance < radius_m
 *                 (treats the surface as planar at the metre scale; the
 *                 chord-vs-arc error is below 1 cm for radii < 200 m).
 *   cylinder_3d — circle_2d test PLUS altitude_m within [min, max].
 *   polygon_2d  — point-in-polygon on the projected WGS84 lat/lon plane.
 *                 Standard ray-casting test; polygons are assumed simple
 *                 (non-self-intersecting); the engine does not check.
 *   bbox_2d     — point-in-rectangle on lat/lon. Cheapest possible test.
 *
 * Most-specific match wins (largest `priority` integer). Ties broken by
 * `id` lexicographic order. The §8 default priorities make this naturally
 * select cylinder_3d > circle_2d > polygon_2d > bbox_2d when the user
 * hasn't overridden them.
 */

import {
  LINK_ZONE_SHAPE_TYPES,
  LINK_ZONE_DEFAULT_PRIORITY,
  ecefChordDistance,
  wgs84ToEcef,
  type LinkZoneShapeType,
  type Wgs84Point,
} from '../spec/index.js';
import type { GeoFix } from './geoSource.js';

/** A zone definition (RFC §8). Stored in `~/.brightchain/brightnexus/geo-zones.json`. */
export interface ZoneDefinition {
  id: string;
  displayName: string;
  shape: ZoneShape;
  /** Override of the §8 default priority for the shape type. Higher wins. */
  priority?: number;
}

/** The discriminated union of supported shape types (RFC §8). */
export type ZoneShape =
  | Circle2d
  | Cylinder3d
  | Polygon2d
  | Bbox2d;

export interface Circle2d {
  type: typeof LINK_ZONE_SHAPE_TYPES.CIRCLE_2D;
  /** Centre. Either `wgs84` or `brightspace` must be set; the engine will
   *  use whichever is provided and convert to ECEF for the test. */
  center: { wgs84: { lat: number; lon: number; alt_m?: number } };
  radius_m: number;
}

export interface Cylinder3d {
  type: typeof LINK_ZONE_SHAPE_TYPES.CYLINDER_3D;
  center: { wgs84: { lat: number; lon: number } };
  radius_m: number;
  altitude_min_m: number;
  altitude_max_m: number;
}

export interface Polygon2d {
  type: typeof LINK_ZONE_SHAPE_TYPES.POLYGON_2D;
  points_wgs84: Array<{ lat: number; lon: number }>;
}

export interface Bbox2d {
  type: typeof LINK_ZONE_SHAPE_TYPES.BBOX_2D;
  lat_min: number;
  lat_max: number;
  lon_min: number;
  lon_max: number;
}

/** Resolved priority for a zone (explicit `priority` if set, else default). */
export function zonePriority(zone: ZoneDefinition): number {
  return zone.priority ?? LINK_ZONE_DEFAULT_PRIORITY[zone.shape.type];
}

/** Test whether a fix is inside a single zone shape. */
export function pointInZone(fix: GeoFix, zone: ZoneDefinition): boolean {
  const shape = zone.shape;
  switch (shape.type) {
    case LINK_ZONE_SHAPE_TYPES.CIRCLE_2D: {
      // Ground-projected ECEF: drop altitude to ellipsoid surface for both
      // points so the chord measures along the surface plane.
      const centerWgs84: Wgs84Point = {
        lat: shape.center.wgs84.lat,
        lon: shape.center.wgs84.lon,
        alt_m: 0,
      };
      const fixGround: Wgs84Point = {
        lat: fix.wgs84.lat,
        lon: fix.wgs84.lon,
        alt_m: 0,
      };
      const c = wgs84ToEcef(centerWgs84);
      const f = wgs84ToEcef(fixGround);
      return ecefChordDistance(c, f) <= shape.radius_m;
    }
    case LINK_ZONE_SHAPE_TYPES.CYLINDER_3D: {
      // 2D test + altitude band.
      const centerWgs84: Wgs84Point = {
        lat: shape.center.wgs84.lat,
        lon: shape.center.wgs84.lon,
        alt_m: 0,
      };
      const fixGround: Wgs84Point = {
        lat: fix.wgs84.lat,
        lon: fix.wgs84.lon,
        alt_m: 0,
      };
      const c = wgs84ToEcef(centerWgs84);
      const f = wgs84ToEcef(fixGround);
      const horizontalOk = ecefChordDistance(c, f) <= shape.radius_m;
      const fixAlt = fix.wgs84.alt_m ?? 0;
      const verticalOk =
        fixAlt >= shape.altitude_min_m && fixAlt <= shape.altitude_max_m;
      return horizontalOk && verticalOk;
    }
    case LINK_ZONE_SHAPE_TYPES.POLYGON_2D:
      return pointInPolygon(fix.wgs84, shape.points_wgs84);
    case LINK_ZONE_SHAPE_TYPES.BBOX_2D:
      return (
        fix.wgs84.lat >= shape.lat_min &&
        fix.wgs84.lat <= shape.lat_max &&
        fix.wgs84.lon >= shape.lon_min &&
        fix.wgs84.lon <= shape.lon_max
      );
    default: {
      // Type-narrowing guard. Reached only if a new shape is added without
      // updating this switch.
      const _exhaustive: never = shape;
      void _exhaustive;
      return false;
    }
  }
}

/** Standard ray-casting point-in-polygon. Returns true if the point lies
 *  inside the polygon (including the boundary up to FP rounding). The
 *  polygon is assumed simple (non-self-intersecting). */
function pointInPolygon(
  point: { lat: number; lon: number },
  polygon: Array<{ lat: number; lon: number }>,
): boolean {
  if (polygon.length < 3) return false;
  const x = point.lon;
  const y = point.lat;
  let inside = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const xi = polygon[i].lon;
    const yi = polygon[i].lat;
    const xj = polygon[j].lon;
    const yj = polygon[j].lat;
    const intersect =
      yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi;
    if (intersect) inside = !inside;
  }
  return inside;
}

/** The zone engine: holds the user's zone definitions and answers
 *  "what zone am I in?" given a fix. RFC §8. */
export class LinkZoneEngine {
  private zones: ZoneDefinition[] = [];

  /** Replace the zone list. The engine takes ownership of the array. */
  setZones(zones: ZoneDefinition[]): void {
    this.zones = [...zones];
  }

  /** All currently-loaded zones (a defensive copy). */
  list(): ZoneDefinition[] {
    return [...this.zones];
  }

  /** Look up by id; returns null if not found. */
  byId(id: string): ZoneDefinition | null {
    return this.zones.find((z) => z.id === id) ?? null;
  }

  /** Return the highest-priority zone the fix is inside, or null if none. */
  currentZone(fix: GeoFix): ZoneDefinition | null {
    let best: ZoneDefinition | null = null;
    let bestPriority = -Infinity;
    for (const zone of this.zones) {
      if (!pointInZone(fix, zone)) continue;
      const p = zonePriority(zone);
      if (
        p > bestPriority ||
        (p === bestPriority && best !== null && zone.id < best.id)
      ) {
        best = zone;
        bestPriority = p;
      }
    }
    return best;
  }
}
