/**
 * `mock-brightnexus` — public surface.
 *
 *   import { MockBrightNexus } from '@harness/mock-brightnexus';
 *   const mock = new MockBrightNexus();
 *   await mock.start('/tmp/test-bridge.sock');
 *   // ... run tests against mock.getSocketPath() ...
 *   await mock.stop();
 */

export { MockBrightNexus } from './socketServer.js';
export type {
  LinkSession,
  AuditEvent,
  PushEvent,
  MockBrightNexusOptions,
} from './types.js';
export { EciesDecryptError } from './eciesKey.js';

// Geo Wave 2 surface — the abstractions and mock implementations tests
// use to drive the geo flow.

// Bridge identity
export { SoftwareBridgeIdentity, computeKeyId } from './bridgeIdentity.js';
export type { BridgeIdentity } from './bridgeIdentity.js';

// Peer attestation
export {
  MockPeerAttestationProvider,
  DEFAULT_UNSIGNED_ATTESTATION,
  BSH_SHELL_ATTESTATION,
  AWS_CLI_ATTESTATION,
  withSshSession,
} from './peerAttestation.js';
export type {
  PeerAttestation,
  PeerAttestationProvider,
  PidPathSigning,
  SshSessionInfo,
} from './peerAttestation.js';

// Geo source
export { FixedGeoSource, projectFix } from './geoSource.js';
export type {
  GeoFix,
  GeoSource,
  GeoSourceStatus,
  GeoError,
} from './geoSource.js';

// Zone engine
export { LinkZoneEngine, pointInZone, zonePriority } from './zoneEngine.js';
export type {
  ZoneDefinition,
  ZoneShape,
  Circle2d,
  Cylinder3d,
  Polygon2d,
  Bbox2d,
} from './zoneEngine.js';

// ACL
export { LinkAcl, emptyAcl, canonicalJsonBytes } from './acl.js';
export type {
  LinkAclEntry,
  LinkAclDocument,
  AclLookupResult,
} from './acl.js';

// Prompt coordinator
export { MockPromptCoordinator, outcomeToPolicy } from './promptCoordinator.js';
export type {
  LinkAclPromptCoordinator,
  PromptOutcome,
  PromptRequest,
} from './promptCoordinator.js';

// Geo engine
export { LinkGeoEngine } from './geoEngine.js';
export type {
  GeoResult,
  CoordinateFormat,
  PreciseLocationResult,
  GeoAuditEntry,
  GeoAuditDecision,
  GeoAuditSink,
  LinkGeoEngineArgs,
} from './geoEngine.js';
