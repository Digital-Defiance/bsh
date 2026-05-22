/**
 * `LinkAcl` — the per-caller geo allowlist (RFC §7.2).
 *
 * The ACL is a list of entries that map a canonical caller identity tuple
 * `(attestation_class, issuer_id, subject_id)` (plus path+hash for the
 * Unsigned class) to per-scope policy values (`always` / `prompt` / `deny`).
 *
 * The mock holds the ACL in memory. The real bridge persists it to
 * `~/.brightchain/brightnexus/geo-acl.json` along with a detached
 * `geo-acl.sig` signed by `BridgeIdentity`. The mock simulates that pairing
 * — every mutation re-signs the canonical-JSON encoding using the supplied
 * `BridgeIdentity`, and the `verify()` method re-canonicalises and checks
 * the signature.
 *
 * Tampering: a test that wants to simulate user-edit tampering can call
 * `getCanonicalJson()`, mutate it, and call `loadFromJson()` with the
 * tampered bytes — the load detects the signature mismatch and reverts
 * every entry to `prompt`, exactly as the real bridge does (§7.2 last
 * paragraph).
 */

import type { Buffer } from 'node:buffer';
import { createPublicKey, createVerify } from 'node:crypto';

import {
  LINK_GEO_SCOPES,
  LINK_GEO_SCOPE_RANK,
  LINK_GEO_UNSIGNED_MAX_SCOPE,
  LINK_GEO_POLICIES,
  LINK_ATTESTATION_CLASSES,
  type LinkGeoScope,
  type LinkGeoPolicy,
  type LinkAttestationClass,
} from '../spec/index.js';
import type { BridgeIdentity } from './bridgeIdentity.js';
import type { PeerAttestation } from './peerAttestation.js';

/** A single ACL entry — one caller's policy. RFC §7.2. */
export interface LinkAclEntry {
  /** ULID-ish stable id. */
  id: string;
  /** Human-readable label for the GUI. */
  displayName: string;
  attestationClass: LinkAttestationClass;
  issuerId: string | null;
  subjectId: string | null;
  /** Sanity-check display field. The bridge trusts the signing identity,
   *  not the path. */
  expectedPath: string | null;
  /** SHA-256 of the binary as `"sha256:..."`. Only meaningful for
   *  unsigned binaries; null otherwise. */
  fallbackHash: string | null;
  scopes: Record<LinkGeoScope, LinkGeoPolicy>;
  addedAtBd: number;
  lastUsedBd: number;
  /** Optional auto-expire BrightDate. null = never expires. */
  expiresAtBd: number | null;
  purpose?: string;
  /** For session-scoped grants only: tied to a specific SSH session id. */
  sshSessionId?: string;
}

/** The full ACL document. The `bridgeKeyId` field pins the file to a
 *  specific bridge identity so the file invalidates if moved between
 *  bridges (RFC §7.2). */
export interface LinkAclDocument {
  version: 1;
  bridgeKeyId: string;
  entries: LinkAclEntry[];
}

/** Result of ACL lookup against an attestation + scope. */
export type AclLookupResult =
  | { kind: 'allow'; entry: LinkAclEntry }
  | { kind: 'deny'; entry: LinkAclEntry; reason: 'policy' }
  | { kind: 'prompt'; entry: LinkAclEntry | null }
  | { kind: 'deny-cap'; reason: 'unsigned-binary-cap' };

/** The §7.1 default scope grants for all entries. */
function defaultPromptScopes(): Record<LinkGeoScope, LinkGeoPolicy> {
  return {
    [LINK_GEO_SCOPES.STATUS]: LINK_GEO_POLICIES.PROMPT,
    [LINK_GEO_SCOPES.PROXIMITY]: LINK_GEO_POLICIES.PROMPT,
    [LINK_GEO_SCOPES.ZONE]: LINK_GEO_POLICIES.PROMPT,
    [LINK_GEO_SCOPES.PRECISE]: LINK_GEO_POLICIES.PROMPT,
    [LINK_GEO_SCOPES.TRAJECTORY]: LINK_GEO_POLICIES.PROMPT,
  };
}

/** Build a fresh ACL with no entries, pinned to the supplied bridge id. */
export function emptyAcl(bridgeKeyId: string): LinkAclDocument {
  return { version: 1, bridgeKeyId, entries: [] };
}

/** The mock's in-memory ACL. */
export class LinkAcl {
  private doc: LinkAclDocument;
  private signature: Buffer | null = null;
  private readonly identity: BridgeIdentity;

  constructor(identity: BridgeIdentity, initial?: LinkAclDocument) {
    this.identity = identity;
    this.doc = initial ?? emptyAcl(identity.keyId());
    this.resign();
  }

  /** All entries (defensive copy). */
  list(): LinkAclEntry[] {
    return this.doc.entries.map((e) => ({ ...e }));
  }

  /** The bridge identity this ACL is pinned to. */
  bridgeKeyId(): string {
    return this.doc.bridgeKeyId;
  }

  /** Add or replace an entry. Re-signs the document. The entry's `addedAtBd`
   *  is left as supplied so tests can pin determinism. */
  upsert(entry: LinkAclEntry): void {
    const existing = this.doc.entries.findIndex((e) => e.id === entry.id);
    if (existing >= 0) {
      this.doc.entries[existing] = { ...entry };
    } else {
      this.doc.entries.push({ ...entry });
    }
    this.resign();
  }

  /** Remove an entry by id. */
  remove(id: string): void {
    this.doc.entries = this.doc.entries.filter((e) => e.id !== id);
    this.resign();
  }

  /** Look up an attestation against the ACL for the requested scope.
   *  Returns the policy decision per RFC §7.4. */
  lookup(
    attestation: PeerAttestation,
    scope: LinkGeoScope,
    nowBd: number,
  ): AclLookupResult {
    // §7.1 cap: unsigned binaries cannot receive geo:zone or higher.
    if (
      attestation.attestationClass === LINK_ATTESTATION_CLASSES.UNSIGNED &&
      LINK_GEO_SCOPE_RANK[scope] > LINK_GEO_SCOPE_RANK[LINK_GEO_UNSIGNED_MAX_SCOPE]
    ) {
      return { kind: 'deny-cap', reason: 'unsigned-binary-cap' };
    }

    const entry = this.findMatchingEntry(attestation);
    if (entry === null) {
      return { kind: 'prompt', entry: null };
    }

    // Auto-expire entries past `expiresAtBd`.
    if (entry.expiresAtBd !== null && nowBd > entry.expiresAtBd) {
      // Treat expired entries as "no entry" — the prompt fires fresh.
      return { kind: 'prompt', entry: null };
    }

    const policy = entry.scopes[scope];
    if (policy === LINK_GEO_POLICIES.ALWAYS) {
      return { kind: 'allow', entry };
    }
    if (policy === LINK_GEO_POLICIES.DENY) {
      return { kind: 'deny', entry, reason: 'policy' };
    }
    return { kind: 'prompt', entry };
  }

  /** Find an entry matching an attestation. Used internally by lookup
   *  and exposed for tests. */
  findMatchingEntry(attestation: PeerAttestation): LinkAclEntry | null {
    for (const entry of this.doc.entries) {
      if (entry.attestationClass !== attestation.attestationClass) continue;
      if (entry.attestationClass === LINK_ATTESTATION_CLASSES.UNSIGNED) {
        // Unsigned entries match by (path, hash). Both must match.
        if (entry.expectedPath !== attestation.executablePath) continue;
        if (entry.fallbackHash === null || attestation.executableHash === null) {
          continue;
        }
        const expected = entry.fallbackHash.replace(/^sha256:/, '');
        if (expected !== attestation.executableHash.toString('hex')) {
          continue;
        }
        return entry;
      }
      // Signed entries match on (issuerId, subjectId).
      if (entry.issuerId !== attestation.issuerId) continue;
      if (entry.subjectId !== attestation.subjectId) continue;
      return entry;
    }
    return null;
  }

  /** Mark `lastUsedBd` after a successful access. Re-signs. */
  recordUse(entryId: string, nowBd: number): void {
    const entry = this.doc.entries.find((e) => e.id === entryId);
    if (!entry) return;
    entry.lastUsedBd = nowBd;
    this.resign();
  }

  /** Canonical-JSON-encoded form of the document, byte-stable for
   *  signing. The encoding is RFC 8785 JCS-style: sorted keys, no
   *  whitespace, no insignificant trailing zeros. */
  getCanonicalJson(): Buffer {
    return canonicalJsonBytes(this.doc);
  }

  /** Detached signature over the canonical-JSON encoding. */
  getSignature(): Buffer {
    if (this.signature === null) {
      throw new Error('ACL has not been signed yet (internal bug)');
    }
    return Buffer.from(this.signature);
  }

  /** Verify the in-memory document against the in-memory signature. */
  verify(): boolean {
    if (this.signature === null) return false;
    return verifyEcdsaP256(
      this.identity.publicKey(),
      this.getCanonicalJson(),
      this.signature,
    );
  }

  /** Load an ACL from canonical-JSON bytes + a detached signature. If the
   *  signature does not verify (or the bridge key id mismatches), the
   *  document is loaded with every entry's policy reverted to `prompt`,
   *  exactly as the real bridge does on tamper detection (§7.2). */
  loadFromBytes(canonicalJson: Buffer, signature: Buffer): { tampered: boolean } {
    let parsed: LinkAclDocument | null = null;
    try {
      parsed = JSON.parse(canonicalJson.toString('utf8')) as LinkAclDocument;
    } catch {
      this.doc = emptyAcl(this.identity.keyId());
      this.resign();
      return { tampered: true };
    }
    const sigOk = verifyEcdsaP256(
      this.identity.publicKey(),
      canonicalJson,
      signature,
    );
    const keyIdOk = parsed.bridgeKeyId === this.identity.keyId();
    if (!sigOk || !keyIdOk) {
      // Tamper detection: revert every entry to prompt, re-sign with the
      // current bridge identity.
      for (const e of parsed?.entries ?? []) {
        e.scopes = defaultPromptScopes();
      }
      this.doc = parsed
        ? { ...parsed, bridgeKeyId: this.identity.keyId() }
        : emptyAcl(this.identity.keyId());
      this.resign();
      return { tampered: true };
    }
    this.doc = parsed;
    this.signature = Buffer.from(signature);
    return { tampered: false };
  }

  private resign(): void {
    const canonical = canonicalJsonBytes(this.doc);
    this.signature = this.identity.sign(canonical);
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Canonical JSON (RFC 8785 JCS, restricted to the shapes we serialise)
// ────────────────────────────────────────────────────────────────────────────

/** RFC 8785 JCS encoding restricted to the shapes the ACL/zones modules
 *  produce: objects with sorted keys, arrays in source order, primitive
 *  scalars (string, number, bool, null). No NaN / Infinity. */
export function canonicalJsonBytes(value: unknown): Buffer {
  return Buffer.from(canonicalJsonString(value), 'utf8');
}

function canonicalJsonString(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('canonical JSON forbids NaN / Infinity');
    }
    // Use the same shortest-round-trip serialization Node's JSON.stringify
    // uses — which is bit-stable for finite numbers.
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJsonString).join(',') + ']';
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      const v = obj[k];
      if (v === undefined) continue;
      parts.push(JSON.stringify(k) + ':' + canonicalJsonString(v));
    }
    return '{' + parts.join(',') + '}';
  }
  throw new Error(`canonical JSON does not support ${typeof value}`);
}

// ────────────────────────────────────────────────────────────────────────────
// ECDSA-P256 verify (matches what BridgeIdentity.sign produces — DER-encoded
// signature over a SHA-256 digest of the input).
// ────────────────────────────────────────────────────────────────────────────

function verifyEcdsaP256(
  pubKey65: Buffer,
  data: Buffer,
  signatureDer: Buffer,
): boolean {
  if (pubKey65.length !== 65 || pubKey65[0] !== 0x04) return false;
  try {
    const x = pubKey65.subarray(1, 33);
    const y = pubKey65.subarray(33, 65);
    const jwk = {
      kty: 'EC' as const,
      crv: 'P-256' as const,
      x: x.toString('base64url'),
      y: y.toString('base64url'),
    };
    const pubKey = createPublicKey({ key: jwk, format: 'jwk' });
    const verifier = createVerify('SHA256');
    verifier.update(data);
    return verifier.verify({ key: pubKey, dsaEncoding: 'der' }, signatureDer);
  } catch {
    return false;
  }
}
