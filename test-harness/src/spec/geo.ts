/**
 * Geo-socket protocol spec (RFC §6, §7, §10).
 *
 * The geo socket is a *separate* Unix socket from the main EBP/1 + BrightLink surface.
 * It exists so child processes (e.g. arbitrary scripts under
 * ~/.config/bsh/geo-triggers.d/, the `bsh-geo` helper, the `bsh-geo-override`
 * helper) can read location data without going through an BrightLink session.
 *
 * Authentication is by:
 *   1. Peer UID match (SO_PEERCRED on Linux, LOCAL_PEERCRED on macOS).
 *   2. Allowlist membership of the peer's resolved executable path.
 *   3. Optional SHA-256 hash check on the executable.
 *   4. Optional per-program approval cache (Touch ID prompt).
 */

// ────────────────────────────────────────────────────────────────────────────
// Filesystem layout (RFC §7.2 + BrightNexus README)
// ────────────────────────────────────────────────────────────────────────────

/** Geo path-file relative to $HOME. The bridge writes the live socket path
 *  into this file atomically on startup; clients read this file first to
 *  discover where the geo socket actually is. // RFC §7.2 */
export const GEO_PATH_FILE_RELATIVE = '.brightchain/brightnexus/brightnexus.geo.path';

/** Filename pattern for the live geo socket. The `<random>` component is 16
 *  lowercase hex chars per RFC §4.1's squat-resistance rule. */
export const GEO_SOCKET_FILENAME_PATTERN = /^brightnexus-[0-9a-f]{16}\.geo\.sock$/;

/** Build a geo socket path: ~/.brightchain/brightnexus/brightnexus-<rand>.geo.sock */
export function buildGeoSocketPath(home: string, randomComponent: string): string {
  if (!/^[0-9a-f]{16}$/.test(randomComponent)) {
    throw new Error(
      `randomComponent must be 16 lowercase hex chars; got "${randomComponent}"`,
    );
  }
  return `${home}/.brightchain/brightnexus/brightnexus-${randomComponent}.geo.sock`;
}

/** Environment variable bsh exports to children pointing at the path-file
 *  (NOT directly at the live socket). Clients re-read this on every request
 *  to survive bridge restarts. // RFC §7.2 */
export const BSH_GEO_SOCK_ENV_VAR = 'BSH_GEO_SOCK';

// ────────────────────────────────────────────────────────────────────────────
// Wire protocol (RFC §7.3)
// ────────────────────────────────────────────────────────────────────────────

/** The geo socket uses newline-terminated JSON, NOT brace-terminated.
 *  // RFC §7.3 explicitly contrasts with EBP/1's framer.
 */
export const GEO_MESSAGE_TERMINATOR = 0x0a; // '\n'

/** Geo socket op values. // RFC §7.3 */
export const GEO_OPS = {
  GET: 'get',
  STATUS: 'status',
  REFRESH: 'refresh',
  AUDIT: 'audit',
} as const;

export type GeoOp = (typeof GEO_OPS)[keyof typeof GEO_OPS];

/** Error values returned in failure payloads. // RFC §5.3.2 + §7.3 */
export const GEO_ERRORS = {
  DENIED: 'denied',
  UNAVAILABLE: 'unavailable',
  EXPIRED: 'expired',
  PRESENCE_FAILED: 'presence_failed',
  NOT_AUTHORIZED: 'not_authorized',
  ALTITUDE_UNKNOWN: 'altitude_unknown',
  RATE_LIMITED: 'rate_limited',
} as const;

export type GeoError = (typeof GEO_ERRORS)[keyof typeof GEO_ERRORS];

// ────────────────────────────────────────────────────────────────────────────
// `geo-context` payload schema (RFC §5.3.1)
// ────────────────────────────────────────────────────────────────────────────

/** Provenance values. // RFC §5.3.1 */
export const GEO_PROVENANCE = {
  HARDWARE: 'hardware',
  NETWORK: 'network',
  /** Used in failure payloads / when no fix exists. */
  NONE: 'none',
} as const;

export type GeoProvenance = (typeof GEO_PROVENANCE)[keyof typeof GEO_PROVENANCE];

/**
 * The success-shape `geo-context` payload as returned by the bridge.
 *
 * Coordinate forms:
 *   - geodetic: WGS84 degrees + metres (the OS-reported authoritative form).
 *   - ecef: BrightSpace ECEF metres (computed from geodetic).
 *   - spacetime: BrightSpaceTime (Bright-Seconds + BrightMeters; Earth-scale
 *                spatial values are small fractions of a BrightMeter, which
 *                is correct — see RFC §5.3.1).
 *
 * Timestamps:
 *   - `issued_at_bd`, `expires_at_bd`: BrightDate scalars (days since J2000.0).
 *   - `ttl_seconds`: convenience integer.
 */
export interface GeoContextPayload {
  type: 'geo-context';
  context: string; // routing context
  issued_at_bd: number;
  expires_at_bd: number;
  ttl_seconds: number;
  zones_entered: string[];
  zones_exited: string[];
  geodetic: {
    latitude: number;
    longitude: number;
    altitude: number | null;
  };
  ecef: { x: number; y: number; z: number };
  spacetime: { t: number; x: number; y: number; z: number };
  altitude_assumed: boolean;
  accuracy_metres: number;
  provenance: GeoProvenance;
  user_presence: boolean;
}

/** The failure shape. // RFC §5.3.2 */
export interface GeoContextFailurePayload {
  type: 'geo-context';
  context: string;
  issued_at_bd: number;
  expires_at_bd: number;
  error: GeoError;
}

// ────────────────────────────────────────────────────────────────────────────
// Allowlist file format (RFC §7.5)
// ────────────────────────────────────────────────────────────────────────────

/** Default location of the user-owned allowlist. The bridge MUST refuse to
 *  honor this file if it is group- or world-writable. // RFC §6.1, §7.5 */
export const GEO_ALLOWLIST_PATH_RELATIVE = '.config/bsh/geo-allow';

/** Default location of the user-owned zone definitions. Same permissions
 *  rules. // RFC §6.1 */
export const GEO_ZONES_PATH_RELATIVE = '.config/bsh/geo-zones';

/** Default location of the trigger file pushed to bsh on session start. The
 *  bridge reads this; bsh receives the parsed `command_jit` target list via
 *  LINK_PUSH (RFC §10.1) and never reads the file directly. */
export const GEO_TRIGGERS_PATH_RELATIVE = '.config/bsh/geo-triggers';

// ────────────────────────────────────────────────────────────────────────────
// Rate limits and approvals (RFC §7.4, §10.3)
// ────────────────────────────────────────────────────────────────────────────

/** Maximum successful `get` requests per minute per peer PID. // RFC §7.4 */
export const GEO_RATE_LIMIT_GETS_PER_MINUTE = 60;

/** Default per-program approval cache lifetime in seconds. // RFC §7.4
 *  Configurable per-allowlist-entry via `approve_ttl=<seconds>`. */
export const GEO_APPROVAL_CACHE_DEFAULT_TTL_SECONDS = 300;

/** Default presence-cache lifetime. // RFC §10.3 */
export const GEO_PRESENCE_CACHE_DEFAULT_TTL_SECONDS = 30;

/** Maximum value users can configure in `~/.config/bsh/geo-presence-ttl`. */
export const GEO_PRESENCE_CACHE_MAX_TTL_SECONDS = 300;

// ────────────────────────────────────────────────────────────────────────────
// `bsh-geo` helper exit codes (RFC §7.6)
// ────────────────────────────────────────────────────────────────────────────

export const BSH_GEO_EXIT_CODES = {
  OK: 0,
  NO_FIX: 1,
  BRIDGE_UNREACHABLE: 2,
  NOT_AUTHORIZED: 3,
  ALTITUDE_UNKNOWN: 4,
  RATE_LIMITED: 5,
} as const;

/** `bsh-geo-override` calls that are advisory-refused by bsh return this exit
 *  code (RFC §6.5.2). 124 chosen to avoid POSIX EX_NOPERM (77) and the
 *  126/127 shell-builtin collisions. */
export const BSH_ADVISORY_REFUSAL_EXIT_CODE = 124;
