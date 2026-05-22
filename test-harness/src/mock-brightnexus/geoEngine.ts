/**
 * `LinkGeoEngine` — the orchestrator that ties `GeoSource`, `LinkZoneEngine`,
 * `LinkAcl`, and `LinkAclPromptCoordinator` together.
 *
 * Every `LINK_GEO_*` request flows through one of the public methods on
 * this class. The flow per RFC §7.4 / §9 is:
 *
 *   1. Look up the caller's attestation in the ACL.
 *   2. If the entry says `always` → return data.
 *   3. If the entry says `deny` → return error.
 *   4. If the entry says `prompt` (or no entry) → ask the prompt coordinator.
 *   5. On `allow_always` / `deny_always` → upsert the ACL entry, return data.
 *   6. On `allow_once` → return data without persisting.
 *   7. On `deny` / `timeout` → return error.
 *
 * Every decision is recorded in the bridge's audit log (RFC §7.7). Audit
 * entries are queryable directly through `BridgeState.auditLog` for tests.
 *
 * `LINK_GEO_STATUS` is the only command that bypasses the ACL, per §9.1 —
 * it carries no location data and is needed for graceful degradation.
 */

import {
  LINK_ATTESTATION_CLASSES,
  LINK_GEO_ERRORS,
  LINK_GEO_POLICIES,
  LINK_GEO_SCOPES,
  ecefToBrightSpace,
  type LinkGeoScope,
} from '../spec/index.js';
import type { LinkAcl, LinkAclEntry } from './acl.js';
import type { GeoSource } from './geoSource.js';
import type { PeerAttestation } from './peerAttestation.js';
import type {
  LinkAclPromptCoordinator,
  PromptOutcome,
} from './promptCoordinator.js';
import {
  pointInZone,
  type LinkZoneEngine,
  type ZoneDefinition,
} from './zoneEngine.js';

/** The result shape returned by every geo method. The handlers wrap this
 *  into the actual JSON response. */
export type GeoResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: string };

/** The format the caller wants for `LINK_GEO_GET`. RFC §9.4. */
export type CoordinateFormat = 'wgs84' | 'brightspace' | 'both';

/** What `LINK_GEO_GET` returns. */
export interface PreciseLocationResult {
  position: {
    wgs84?: { lat: number; lon: number; alt_m?: number };
    brightspace?: {
      x_bm: number;
      y_bm: number;
      z_bm: number;
      epoch_bd: number;
    };
  };
  accuracy_m: number;
  brightdate: number;
}

/** Audit-event kinds emitted by the geo engine. RFC §7.7. */
export type GeoAuditDecision =
  | 'allowed_by_acl'
  | 'allowed_by_prompt'
  | 'denied_by_acl'
  | 'denied_by_prompt'
  | 'denied_unsigned_cap'
  | 'prompt_timeout'
  | 'throttled'
  | 'engine_unavailable';

export interface GeoAuditEntry {
  brightdate: number;
  command: string;
  scope: LinkGeoScope;
  decision: GeoAuditDecision;
  policyAtDecision: string | null;
  attestation: PeerAttestation;
  responseSummary: Record<string, unknown>;
}

/** The audit-log sink the engine writes through. The bridge's
 *  `BridgeState.auditLog` already implements this shape. */
export interface GeoAuditSink {
  recordGeoEvent(entry: GeoAuditEntry): void;
}

/** Construction args. */
export interface LinkGeoEngineArgs {
  source: GeoSource;
  zones: LinkZoneEngine;
  acl: LinkAcl;
  prompt: LinkAclPromptCoordinator;
  audit: GeoAuditSink;
  /** BrightDate clock. */
  nowBd: () => number;
  /** Hold-open prompt timeout (RFC §7.5). Default 30s. */
  promptTimeoutSeconds?: number;
  /** Default scope policy when no ACL entry exists. Default: `prompt`. */
  defaultScopePolicy?: typeof LINK_GEO_POLICIES.PROMPT
    | typeof LINK_GEO_POLICIES.DENY
    | typeof LINK_GEO_POLICIES.ALWAYS;
}

/** Track the current zone for dwell-time and zone-transition reporting. */
interface ZoneTrackerState {
  zoneId: string | null;
  enteredAtBd: number;
}

export class LinkGeoEngine {
  private readonly source: GeoSource;
  private readonly zones: LinkZoneEngine;
  private readonly acl: LinkAcl;
  private readonly prompt: LinkAclPromptCoordinator;
  private readonly audit: GeoAuditSink;
  private readonly nowBd: () => number;
  private readonly promptTimeoutSeconds: number;
  private readonly defaultScopePolicy:
    | typeof LINK_GEO_POLICIES.PROMPT
    | typeof LINK_GEO_POLICIES.DENY
    | typeof LINK_GEO_POLICIES.ALWAYS;
  private zoneTracker: ZoneTrackerState = {
    zoneId: null,
    enteredAtBd: 0,
  };
  /** Subscribers notified on zone transitions. The push channel uses this. */
  private zoneTransitionHandlers: Array<
    (event: { from: string | null; to: string | null; atBd: number }) => void
  > = [];

  constructor(args: LinkGeoEngineArgs) {
    this.source = args.source;
    this.zones = args.zones;
    this.acl = args.acl;
    this.prompt = args.prompt;
    this.audit = args.audit;
    this.nowBd = args.nowBd;
    this.promptTimeoutSeconds = args.promptTimeoutSeconds ?? 30;
    this.defaultScopePolicy = args.defaultScopePolicy ?? LINK_GEO_POLICIES.PROMPT;

    // Subscribe to fix updates so we can detect zone transitions and emit
    // push events.
    this.source.subscribe(() => this.evaluateZoneTransition());
  }

  // ──────────────────────────────────────────────────────────────────────
  // Public methods (one per LINK_GEO_* command, plus the push helpers)
  // ──────────────────────────────────────────────────────────────────────

  /** §9.1 LINK_GEO_STATUS — alive + fix age, no scope gate. */
  status(_attestation: PeerAttestation): GeoResult<{
    alive: boolean;
    engineKind: string;
    fixAgeSeconds: number | null;
    accuracyM: number | null;
  }> {
    const status = this.source.status();
    return {
      ok: true,
      value: {
        alive: status.alive,
        engineKind: status.kind,
        fixAgeSeconds: status.fix_age_seconds,
        accuracyM: status.accuracy_m,
      },
    };
  }

  /** §9.2 LINK_GEO_PROXIMITY — yes/no for a named zone. */
  async proximity(
    attestation: PeerAttestation,
    zoneId: string,
  ): Promise<GeoResult<{ inZone: boolean; brightdate: number }>> {
    const decision = await this.gateScope(
      attestation,
      LINK_GEO_SCOPES.PROXIMITY,
      'LINK_GEO_PROXIMITY',
      { zoneId },
    );
    if (!decision.ok) return decision;

    const zone = this.zones.byId(zoneId);
    if (zone === null) {
      this.audit.recordGeoEvent({
        brightdate: this.nowBd(),
        command: 'LINK_GEO_PROXIMITY',
        scope: LINK_GEO_SCOPES.PROXIMITY,
        decision: 'engine_unavailable',
        policyAtDecision: null,
        attestation,
        responseSummary: { error: 'zone_not_found', zoneId },
      });
      return { ok: false, error: LINK_GEO_ERRORS.ZONE_NOT_FOUND };
    }

    const fix = this.source.currentFix();
    if (fix === null) {
      this.audit.recordGeoEvent({
        brightdate: this.nowBd(),
        command: 'LINK_GEO_PROXIMITY',
        scope: LINK_GEO_SCOPES.PROXIMITY,
        decision: 'engine_unavailable',
        policyAtDecision: null,
        attestation,
        responseSummary: { error: 'no_fix' },
      });
      return { ok: false, error: LINK_GEO_ERRORS.ENGINE_UNAVAILABLE };
    }

    // Inline shape evaluation — pulls in the same code path the
    // currentZone() tracker uses but answers a yes/no for one zone.
    const matches = this.zoneMatches(fix, zone);
    return {
      ok: true,
      value: { inZone: matches, brightdate: fix.brightdate },
    };
  }

  /** §9.3 LINK_GEO_ZONE — current zone identifier + dwell. */
  async zone(
    attestation: PeerAttestation,
  ): Promise<
    GeoResult<{
      zone: string | null;
      dwellSeconds: number;
      brightdate: number;
    }>
  > {
    const decision = await this.gateScope(
      attestation,
      LINK_GEO_SCOPES.ZONE,
      'LINK_GEO_ZONE',
      {},
    );
    if (!decision.ok) return decision;

    const fix = this.source.currentFix();
    if (fix === null) {
      this.audit.recordGeoEvent({
        brightdate: this.nowBd(),
        command: 'LINK_GEO_ZONE',
        scope: LINK_GEO_SCOPES.ZONE,
        decision: 'engine_unavailable',
        policyAtDecision: null,
        attestation,
        responseSummary: { error: 'no_fix' },
      });
      return { ok: false, error: LINK_GEO_ERRORS.ENGINE_UNAVAILABLE };
    }

    // Note: this also updates the tracker (and emits push events) if a
    // transition has happened since the last fix.
    this.evaluateZoneTransition();
    const zone = this.zones.currentZone(fix);
    const dwellSeconds = this.dwellSecondsAtNow();
    return {
      ok: true,
      value: {
        zone: zone?.id ?? null,
        dwellSeconds,
        brightdate: fix.brightdate,
      },
    };
  }

  /** §9.4 LINK_GEO_GET — full position. */
  async get(
    attestation: PeerAttestation,
    format: CoordinateFormat,
  ): Promise<GeoResult<PreciseLocationResult>> {
    const decision = await this.gateScope(
      attestation,
      LINK_GEO_SCOPES.PRECISE,
      'LINK_GEO_GET',
      { format },
    );
    if (!decision.ok) return decision;

    const fix = this.source.currentFix();
    if (fix === null) {
      this.audit.recordGeoEvent({
        brightdate: this.nowBd(),
        command: 'LINK_GEO_GET',
        scope: LINK_GEO_SCOPES.PRECISE,
        decision: 'engine_unavailable',
        policyAtDecision: null,
        attestation,
        responseSummary: { error: 'no_fix' },
      });
      return { ok: false, error: LINK_GEO_ERRORS.ENGINE_UNAVAILABLE };
    }

    const position: PreciseLocationResult['position'] = {};
    if (format === 'wgs84' || format === 'both') {
      position.wgs84 = {
        lat: fix.wgs84.lat,
        lon: fix.wgs84.lon,
        ...(fix.wgs84.alt_m !== undefined ? { alt_m: fix.wgs84.alt_m } : {}),
      };
    }
    if (format === 'brightspace' || format === 'both') {
      position.brightspace = ecefToBrightSpace(fix.ecef, fix.brightdate);
    }

    return {
      ok: true,
      value: {
        position,
        accuracy_m: fix.accuracy_m,
        brightdate: fix.brightdate,
      },
    };
  }

  /** §9.5 LINK_GEO_REFRESH — trigger a fresh fix. Gated by the same scope
   *  as the caller's most recent prior get; we treat any allowed scope as
   *  sufficient to trigger a refresh because the data isn't returned here. */
  async refresh(
    attestation: PeerAttestation,
    timeoutSeconds: number,
  ): Promise<
    GeoResult<{ fixAgeSeconds: number; accuracyM: number }>
  > {
    // Refresh is gated by status — the lowest scope that we know the
    // caller has at least implicit access to (it's the only ungated
    // scope). The data comes back via a separate get/zone/proximity call.
    const decision = await this.gateScope(
      attestation,
      LINK_GEO_SCOPES.STATUS,
      'LINK_GEO_REFRESH',
      { timeoutSeconds },
    );
    if (!decision.ok) return decision;

    try {
      const fix = await this.source.requestRefresh(timeoutSeconds * 1000);
      return {
        ok: true,
        value: {
          fixAgeSeconds: 0,
          accuracyM: fix.accuracy_m,
        },
      };
    } catch {
      this.audit.recordGeoEvent({
        brightdate: this.nowBd(),
        command: 'LINK_GEO_REFRESH',
        scope: LINK_GEO_SCOPES.STATUS,
        decision: 'engine_unavailable',
        policyAtDecision: null,
        attestation,
        responseSummary: { error: 'refresh_failed' },
      });
      return { ok: false, error: LINK_GEO_ERRORS.REFRESH_TIMED_OUT };
    }
  }

  // ──────────────────────────────────────────────────────────────────────
  // Push: zone transitions. The socket-server layer subscribes here and
  // emits AAD-sealed LINK_PUSH frames when this fires.
  // ──────────────────────────────────────────────────────────────────────

  onZoneTransition(
    handler: (event: { from: string | null; to: string | null; atBd: number }) => void,
  ): () => void {
    this.zoneTransitionHandlers.push(handler);
    return () => {
      this.zoneTransitionHandlers = this.zoneTransitionHandlers.filter(
        (h) => h !== handler,
      );
    };
  }

  /** Force an immediate re-evaluation of the current zone. Used by tests
   *  to drive transitions deterministically. */
  forceEvaluateZone(): void {
    this.evaluateZoneTransition();
  }

  // ──────────────────────────────────────────────────────────────────────
  // Internals
  // ──────────────────────────────────────────────────────────────────────

  /** Run the §7.4 lookup + §7.5 prompt flow for a single (attestation,
   *  scope) pair. Returns `{ok:true}` on grant or `{ok:false, error}`
   *  otherwise. */
  private async gateScope(
    attestation: PeerAttestation,
    scope: LinkGeoScope,
    command: string,
    extra: Record<string, unknown>,
  ): Promise<GeoResult<true>> {
    const nowBd = this.nowBd();
    const lookup = this.acl.lookup(attestation, scope, nowBd);

    switch (lookup.kind) {
      case 'allow':
        this.acl.recordUse(lookup.entry.id, nowBd);
        this.audit.recordGeoEvent({
          brightdate: nowBd,
          command,
          scope,
          decision: 'allowed_by_acl',
          policyAtDecision: 'always',
          attestation,
          responseSummary: { ...extra },
        });
        return { ok: true, value: true };

      case 'deny':
        this.audit.recordGeoEvent({
          brightdate: nowBd,
          command,
          scope,
          decision: 'denied_by_acl',
          policyAtDecision: 'deny',
          attestation,
          responseSummary: { ...extra },
        });
        return { ok: false, error: LINK_GEO_ERRORS.SCOPE_DENIED_BY_POLICY };

      case 'deny-cap':
        this.audit.recordGeoEvent({
          brightdate: nowBd,
          command,
          scope,
          decision: 'denied_unsigned_cap',
          policyAtDecision: 'unsigned-cap',
          attestation,
          responseSummary: { ...extra },
        });
        return {
          ok: false,
          error: LINK_GEO_ERRORS.SCOPE_UNAVAILABLE_UNSIGNED,
        };

      case 'prompt': {
        const outcome = await this.prompt.prompt({
          attestation,
          scope,
          existingEntry: lookup.entry,
          timeoutSeconds: this.promptTimeoutSeconds,
          reason: lookup.entry === null ? 'no_match' : 'policy_prompt',
        });
        return this.handlePromptOutcome(
          attestation,
          scope,
          command,
          extra,
          outcome,
          lookup.entry,
        );
      }

      default: {
        // Type-narrowing guard.
        const _exhaustive: never = lookup;
        void _exhaustive;
        return { ok: false, error: 'internal: unreachable ACL lookup result' };
      }
    }
  }

  private handlePromptOutcome(
    attestation: PeerAttestation,
    scope: LinkGeoScope,
    command: string,
    extra: Record<string, unknown>,
    outcome: PromptOutcome,
    existing: LinkAclEntry | null,
  ): GeoResult<true> {
    const nowBd = this.nowBd();
    switch (outcome.kind) {
      case 'allow_once':
        this.audit.recordGeoEvent({
          brightdate: nowBd,
          command,
          scope,
          decision: 'allowed_by_prompt',
          policyAtDecision: 'allow_once',
          attestation,
          responseSummary: { ...extra },
        });
        return { ok: true, value: true };

      case 'allow_always': {
        // Persist as `policy=always` for this scope. Upsert into the ACL.
        const entry = this.upsertEntryForScope(
          attestation,
          scope,
          'always',
          existing,
          nowBd,
        );
        this.acl.recordUse(entry.id, nowBd);
        this.audit.recordGeoEvent({
          brightdate: nowBd,
          command,
          scope,
          decision: 'allowed_by_prompt',
          policyAtDecision: 'always',
          attestation,
          responseSummary: { ...extra, persistedAs: 'always' },
        });
        return { ok: true, value: true };
      }

      case 'allow_session':
        // Session-scoped grants live in geo-acl-session.json — for the
        // mock we keep them in the same ACL but tag them with the SSH
        // session id and rely on caller cleanup. The session-id field
        // is what the real bridge keys on for cleanup at SSH session end.
        {
          const entry = this.upsertEntryForScope(
            attestation,
            scope,
            'always',
            existing,
            nowBd,
            { sshSessionId: outcome.sshSessionId },
          );
          this.acl.recordUse(entry.id, nowBd);
          this.audit.recordGeoEvent({
            brightdate: nowBd,
            command,
            scope,
            decision: 'allowed_by_prompt',
            policyAtDecision: 'session',
            attestation,
            responseSummary: { ...extra, sshSessionId: outcome.sshSessionId },
          });
          return { ok: true, value: true };
        }

      case 'deny':
        this.audit.recordGeoEvent({
          brightdate: nowBd,
          command,
          scope,
          decision: 'denied_by_prompt',
          policyAtDecision: 'deny_once',
          attestation,
          responseSummary: { ...extra },
        });
        return { ok: false, error: LINK_GEO_ERRORS.USER_DENIED };

      case 'deny_always': {
        this.upsertEntryForScope(
          attestation,
          scope,
          'deny',
          existing,
          nowBd,
        );
        this.audit.recordGeoEvent({
          brightdate: nowBd,
          command,
          scope,
          decision: 'denied_by_prompt',
          policyAtDecision: 'deny',
          attestation,
          responseSummary: { ...extra, persistedAs: 'deny' },
        });
        return { ok: false, error: LINK_GEO_ERRORS.USER_DENIED };
      }

      case 'timeout':
        this.audit.recordGeoEvent({
          brightdate: nowBd,
          command,
          scope,
          decision: 'prompt_timeout',
          policyAtDecision: null,
          attestation,
          responseSummary: { ...extra },
        });
        return { ok: false, error: LINK_GEO_ERRORS.PROMPT_TIMED_OUT };

      default: {
        const _exhaustive: never = outcome;
        void _exhaustive;
        return { ok: false, error: 'internal: unreachable prompt outcome' };
      }
    }
  }

  private upsertEntryForScope(
    attestation: PeerAttestation,
    scope: LinkGeoScope,
    policy: 'always' | 'deny',
    existing: LinkAclEntry | null,
    nowBd: number,
    args: { sshSessionId?: string } = {},
  ): LinkAclEntry {
    const id = existing?.id ?? generateId(nowBd);
    const baseScopes = existing?.scopes ?? {
      [LINK_GEO_SCOPES.STATUS]: 'prompt' as const,
      [LINK_GEO_SCOPES.PROXIMITY]: 'prompt' as const,
      [LINK_GEO_SCOPES.ZONE]: 'prompt' as const,
      [LINK_GEO_SCOPES.PRECISE]: 'prompt' as const,
      [LINK_GEO_SCOPES.TRAJECTORY]: 'prompt' as const,
    };
    const scopes = { ...baseScopes, [scope]: policy };
    const entry: LinkAclEntry = {
      id,
      displayName:
        existing?.displayName ??
        defaultDisplayName(attestation),
      attestationClass: attestation.attestationClass,
      issuerId: attestation.issuerId,
      subjectId: attestation.subjectId,
      expectedPath: attestation.executablePath,
      fallbackHash:
        attestation.attestationClass === LINK_ATTESTATION_CLASSES.UNSIGNED
          ? `sha256:${attestation.executableHash?.toString('hex') ?? ''}`
          : null,
      scopes,
      addedAtBd: existing?.addedAtBd ?? nowBd,
      lastUsedBd: nowBd,
      expiresAtBd: existing?.expiresAtBd ?? null,
      ...(args.sshSessionId !== undefined
        ? { sshSessionId: args.sshSessionId }
        : {}),
    };
    this.acl.upsert(entry);
    return entry;
  }

  /** Re-evaluate the current zone and emit transition events if it changed. */
  private evaluateZoneTransition(): void {
    const fix = this.source.currentFix();
    if (fix === null) return;
    const nowZone = this.zones.currentZone(fix);
    const nowZoneId = nowZone?.id ?? null;
    if (nowZoneId === this.zoneTracker.zoneId) return;
    const fromId = this.zoneTracker.zoneId;
    const toId = nowZoneId;
    this.zoneTracker = { zoneId: nowZoneId, enteredAtBd: fix.brightdate };
    for (const handler of this.zoneTransitionHandlers) {
      try {
        handler({ from: fromId, to: toId, atBd: fix.brightdate });
      } catch {
        // Never let a misbehaving handler abort the iteration.
      }
    }
  }

  private dwellSecondsAtNow(): number {
    if (this.zoneTracker.zoneId === null) return 0;
    const seconds =
      (this.nowBd() - this.zoneTracker.enteredAtBd) * 86_400;
    return Math.max(0, Math.floor(seconds));
  }

  /** Inline copy of the §8 zoneMatches logic. Kept private so we don't
   *  spread shape-evaluation across multiple files. */
  private zoneMatches(
    fix: { wgs84: { lat: number; lon: number; alt_m?: number } },
    zone: ZoneDefinition,
  ): boolean {
    return pointInZone(
      {
        brightdate: this.nowBd(),
        wgs84: fix.wgs84,
        ecef: { x_m: 0, y_m: 0, z_m: 0 }, // recomputed inside pointInZone
        accuracy_m: 0,
        velocity_mps: null,
      },
      zone,
    );
  }
}

/** Quick id generator. ULIDs would be nicer but we don't need lexicographic
 *  ordering; a random 26-char string is fine. */
function generateId(nowBd: number): string {
  const t = Math.floor(nowBd * 1000).toString(36).toUpperCase().padStart(8, '0');
  const r = Math.floor(Math.random() * 0x1_0000_0000)
    .toString(36)
    .toUpperCase()
    .padStart(8, '0');
  return `01${t}${r}`.slice(0, 26).padEnd(26, '0');
}

function defaultDisplayName(attestation: PeerAttestation): string {
  if (attestation.subjectId) return attestation.subjectId;
  if (attestation.executablePath) return attestation.executablePath;
  return `pid ${attestation.pid}`;
}
