/**
 * Mock peer-attestation provider.
 *
 * The real bridge populates `PeerAttestation` from kernel introspection
 * (`getsockopt(LOCAL_PEERPID)` + `proc_pidpath` + `SecStaticCodeCheckValidity`
 * on macOS; `getsockopt(SO_PEERCRED)` + `/proc/<pid>/exe` + dpkg/rpm signature
 * verification on Linux — see RFC §6.2). The mock cannot do any of that; it
 * just lets the test inject the attestation it wants the handler to see.
 *
 * Tests construct a `MockPeerAttestationProvider`, register a script of
 * attestations to return for successive `accept(2)` calls (or a single
 * default), and pass it to `MockBrightNexus`. The socket server pulls one
 * `PeerAttestation` from the provider per accepted connection.
 */

import type { Buffer } from 'node:buffer';
import { LINK_ATTESTATION_CLASSES, type LinkAttestationClass } from '../spec/index.js';

/** Identifies one ancestor process in the peer's parent chain. RFC §6.2. */
export interface PidPathSigning {
  pid: number;
  executablePath: string | null;
  attestationClass: LinkAttestationClass;
  issuerId: string | null;
}

/** SSH session context populated when an `sshd`-class ancestor is detected
 *  in the peer lineage. RFC §6.2 / §7.3 / §9.6. */
export interface SshSessionInfo {
  /** Best-effort source user from `SSH_CONNECTION` (advisory display only,
   *  NEVER used as an ACL key). */
  sourceUser: string | null;
  /** Best-effort source host from `SSH_CONNECTION` / `SSH_CLIENT`. */
  sourceHost: string | null;
  /** PID of the closest sshd-class ancestor. */
  sshdPid: number;
  /** Stable session id: `"sshd:<pid>:<start_time>"`. The session expires
   *  when the matching sshd PID is no longer alive. */
  sessionId: string;
}

/** The bridge's view of the peer that just connected. RFC §6.2. */
export interface PeerAttestation {
  pid: number;
  uid: number;
  /** Kernel-canonical executable path (immune to argv[0] spoofing).
   *  null if the bridge could not resolve it. */
  executablePath: string | null;
  /** SHA-256 of the executable bytes; null if not measurable. */
  executableHash: Buffer | null;
  attestationClass: LinkAttestationClass;
  /** Canonical issuer id for the class. See RFC §6.2 table. */
  issuerId: string | null;
  /** Canonical subject id (bundle/package/binary name). */
  subjectId: string | null;
  /** True iff the platform's signature-verification call passed. */
  signatureValid: boolean;
  /** Ancestors, immediate-first, capped at 8. Empty in tests that don't
   *  populate it; the geo engine treats empty lineage as "not SSH". */
  peerLineage: PidPathSigning[];
  /** Non-null iff an `sshd`-class ancestor was detected by signing identity. */
  sshSession: SshSessionInfo | null;
}

/** A mock provider that returns scripted attestations. Used in tests so
 *  the geo engine can be exercised against a known caller identity. */
export interface PeerAttestationProvider {
  /** Called by the socket server once per accepted connection. The mock
   *  returns whichever attestation the test set up. */
  attest(): PeerAttestation;
}

/** Default attestation: an unsigned local script with PID 99999.
 *  Tests that don't care about attestation get this. */
export const DEFAULT_UNSIGNED_ATTESTATION: PeerAttestation = {
  pid: 99999,
  uid: 1000,
  executablePath: '/tmp/mock-test-binary',
  executableHash: null,
  attestationClass: LINK_ATTESTATION_CLASSES.UNSIGNED,
  issuerId: null,
  subjectId: null,
  signatureValid: false,
  peerLineage: [],
  sshSession: null,
};

/** Convenience: an attestation for the bsh shell signed under our own key.
 *  Tests that simulate "bsh-inject talking to the bridge" use this. */
export const BSH_SHELL_ATTESTATION: PeerAttestation = {
  pid: 4321,
  uid: 1000,
  executablePath: '/opt/homebrew/bin/bsh',
  executableHash: null,
  attestationClass: LINK_ATTESTATION_CLASSES.BSH_BUILTIN,
  issuerId: 'digitaldefiance',
  subjectId: 'org.digitaldefiance.bsh',
  signatureValid: true,
  peerLineage: [
    {
      pid: 4321,
      executablePath: '/opt/homebrew/bin/bsh',
      attestationClass: LINK_ATTESTATION_CLASSES.BSH_BUILTIN,
      issuerId: 'digitaldefiance',
    },
  ],
  sshSession: null,
};

/** Convenience: an attestation for `aws` (Apple Developer ID). Tests use
 *  this to exercise the "third-party signed binary" path. */
export const AWS_CLI_ATTESTATION: PeerAttestation = {
  pid: 7777,
  uid: 1000,
  executablePath: '/usr/local/bin/aws',
  executableHash: null,
  attestationClass: LINK_ATTESTATION_CLASSES.DEVELOPER_ID,
  issuerId: 'WTGFXFA42L',
  subjectId: 'com.amazon.awscli2',
  signatureValid: true,
  peerLineage: [
    {
      pid: 7777,
      executablePath: '/usr/local/bin/aws',
      attestationClass: LINK_ATTESTATION_CLASSES.DEVELOPER_ID,
      issuerId: 'WTGFXFA42L',
    },
  ],
  sshSession: null,
};

/** A scripted provider that returns a queue of attestations. The first
 *  `attest()` call returns the first item in the queue, the second
 *  returns the second, etc. When the queue is exhausted, returns the
 *  default. */
export class MockPeerAttestationProvider implements PeerAttestationProvider {
  private readonly queue: PeerAttestation[] = [];
  private defaultAttestation: PeerAttestation = DEFAULT_UNSIGNED_ATTESTATION;

  /** Set the attestation to return when the queue is empty. Defaults to
   *  the unsigned local-script attestation. */
  setDefault(attestation: PeerAttestation): this {
    this.defaultAttestation = attestation;
    return this;
  }

  /** Push an attestation onto the queue. The next `attest()` call
   *  consumes it. */
  push(attestation: PeerAttestation): this {
    this.queue.push(attestation);
    return this;
  }

  /** Push the same attestation `n` times. */
  pushMany(attestation: PeerAttestation, n: number): this {
    for (let i = 0; i < n; i++) this.queue.push(attestation);
    return this;
  }

  attest(): PeerAttestation {
    return this.queue.shift() ?? this.defaultAttestation;
  }
}

/** Helper that constructs an SSH-context attestation. The lineage is
 *  prepended with an sshd-class ancestor so the geo engine treats the
 *  caller as SSH-routed. */
export function withSshSession(
  base: PeerAttestation,
  args: { sourceUser?: string; sourceHost?: string; sshdPid?: number } = {},
): PeerAttestation {
  const sshdPid = args.sshdPid ?? 4310;
  return {
    ...base,
    peerLineage: [
      ...base.peerLineage,
      {
        pid: sshdPid,
        executablePath: '/usr/sbin/sshd',
        attestationClass: LINK_ATTESTATION_CLASSES.DEVELOPER_ID,
        issuerId: 'apple',
      },
    ],
    sshSession: {
      sourceUser: args.sourceUser ?? 'alice',
      sourceHost: args.sourceHost ?? 'laptop.local',
      sshdPid,
      sessionId: `sshd:${sshdPid}:1779461500`,
    },
  };
}
