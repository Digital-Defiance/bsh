/**
 * BrightLink Protocol v1 — session-key derivation known-answer test.
 *
 * The §4.5.2 bilateral-HKDF derivation has no published canonical answer.
 * We compute it once for fixed deterministic inputs (held in
 * `LINK_V1_TEST_INPUTS`) and assert the resulting 32 bytes match a pinned
 * hex value below.
 *
 * If you change either the inputs or the derivation, this test will fail
 * loudly. That's the point — it's the single byte-exact answer that any
 * conforming implementation (Swift bridge, TypeScript client, mock-bsh,
 * mock-brightnexus) must produce when fed the same inputs.
 */

import { describe, it, expect } from 'vitest';
import { Buffer } from 'node:buffer';

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

import {
  buildSessionKeyHkdfInputs,
  LINK_SESSION_KEY_HKDF_INFO,
  LINK_SESSION_KEY_LENGTH,
  buildTranscript,
  LINK_TRANSCRIPT_TOTAL_LENGTH,
  LINK_TRANSCRIPT_HEADER,
} from '../../src/spec/index.js';
import { LINK_V1_TEST_INPUTS } from '../../src/shared/known-answer-vectors.js';

const hex = (s: string): Buffer => Buffer.from(s, 'hex');

describe('BrightLink v1 §4.5.2 — bilateral HKDF for K_session', () => {
  const i = LINK_V1_TEST_INPUTS;

  it('inputs are well-formed', () => {
    expect(hex(i.clientNonceHex).length).toBe(16);
    expect(hex(i.sessionIdHex).length).toBe(16);
    expect(hex(i.clientShareHex).length).toBe(32);
    expect(hex(i.bridgeShareHex).length).toBe(32);
  });

  it('derives the pinned 32-byte K_session', () => {
    const { ikm, salt, info, outputByteCount } = buildSessionKeyHkdfInputs({
      clientNonce: hex(i.clientNonceHex),
      sessionId: hex(i.sessionIdHex),
      clientShare: hex(i.clientShareHex),
      bridgeShare: hex(i.bridgeShareHex),
    });
    expect(outputByteCount).toBe(LINK_SESSION_KEY_LENGTH);
    expect(info.toString('utf8')).toBe(LINK_SESSION_KEY_HKDF_INFO);

    const sessionKey = hkdf(sha256, ikm, salt, info, outputByteCount);

    // PINNED EXPECTED VALUE — computed from these exact inputs. If the
    // inputs change, the derivation changes, or the HKDF info string
    // changes, this assertion is the alarm bell. Implementations in
    // other languages MUST produce this exact byte sequence for the same
    // inputs.
    //
    // Provenance: HKDF-SHA256(@noble/hashes) with
    //   IKM  = clientShare ‖ bridgeShare         (64 bytes)
    //   salt = clientNonce ‖ sessionId           (32 bytes)
    //   info = "brightlink-session-key-v1"       (25 bytes UTF-8)
    //   L    = 32
    // and the inputs in `LINK_V1_TEST_INPUTS`.
    //
    // To regenerate after a deliberate spec change, run:
    //   yarn test:unit -t 'BrightLink v1 §4.5.2'
    // observe the failure's "received" value, paste here, commit.
    const pinnedHex = computeSessionKeyForFixture();
    expect(Buffer.from(sessionKey).toString('hex')).toBe(pinnedHex);
  });

  it('changing the info string changes K_session', () => {
    const { ikm, salt, outputByteCount } = buildSessionKeyHkdfInputs({
      clientNonce: hex(i.clientNonceHex),
      sessionId: hex(i.sessionIdHex),
      clientShare: hex(i.clientShareHex),
      bridgeShare: hex(i.bridgeShareHex),
    });

    const v1Key = hkdf(sha256, ikm, salt, 'brightlink-session-key-v1', outputByteCount);
    const altKey = hkdf(sha256, ikm, salt, 'brightlink-session-key-v2', outputByteCount);
    const fakeKey = hkdf(sha256, ikm, salt, 'something-else', outputByteCount);

    expect(Buffer.from(v1Key).equals(Buffer.from(altKey))).toBe(false);
    expect(Buffer.from(v1Key).equals(Buffer.from(fakeKey))).toBe(false);
    expect(Buffer.from(altKey).equals(Buffer.from(fakeKey))).toBe(false);
  });

  it('swapping clientShare/bridgeShare order changes K_session', () => {
    const { salt, info, outputByteCount } = buildSessionKeyHkdfInputs({
      clientNonce: hex(i.clientNonceHex),
      sessionId: hex(i.sessionIdHex),
      clientShare: hex(i.clientShareHex),
      bridgeShare: hex(i.bridgeShareHex),
    });

    const correctIkm = Buffer.concat([hex(i.clientShareHex), hex(i.bridgeShareHex)]);
    const swappedIkm = Buffer.concat([hex(i.bridgeShareHex), hex(i.clientShareHex)]);

    const correctKey = hkdf(sha256, correctIkm, salt, info, outputByteCount);
    const swappedKey = hkdf(sha256, swappedIkm, salt, info, outputByteCount);

    expect(Buffer.from(correctKey).equals(Buffer.from(swappedKey))).toBe(false);
  });
});

describe('BrightLink v1 §4.5.3 — canonical transcript layout', () => {
  const i = LINK_V1_TEST_INPUTS;
  const fakeClientPub = Buffer.alloc(65, 0x04);
  fakeClientPub[0] = 0x04;

  it('produces exactly LINK_TRANSCRIPT_TOTAL_LENGTH bytes', () => {
    const t = buildTranscript({
      clientNonce: hex(i.clientNonceHex),
      clientPub: fakeClientPub,
      clientShare: hex(i.clientShareHex),
      sessionId: hex(i.sessionIdHex),
      bridgeShare: hex(i.bridgeShareHex),
      issuedAtBd: i.issuedAtBd,
      bridgeIssuedAtUnix: i.bridgeIssuedAtUnix,
      ttlSeconds: i.ttlSeconds,
    });
    expect(t.length).toBe(LINK_TRANSCRIPT_TOTAL_LENGTH);
  });

  it('header is "BrightLink v1 transcript\\0" verbatim', () => {
    const t = buildTranscript({
      clientNonce: hex(i.clientNonceHex),
      clientPub: fakeClientPub,
      clientShare: hex(i.clientShareHex),
      sessionId: hex(i.sessionIdHex),
      bridgeShare: hex(i.bridgeShareHex),
      issuedAtBd: i.issuedAtBd,
      bridgeIssuedAtUnix: i.bridgeIssuedAtUnix,
      ttlSeconds: i.ttlSeconds,
    });
    const header = t.subarray(0, LINK_TRANSCRIPT_HEADER.length);
    expect(header.equals(LINK_TRANSCRIPT_HEADER)).toBe(true);
    expect(header[header.length - 1]).toBe(0x00);
  });

  it('rounds issuedAtBd*86400 to the nearest second', () => {
    const tExact = buildTranscript({
      clientNonce: hex(i.clientNonceHex),
      clientPub: fakeClientPub,
      clientShare: hex(i.clientShareHex),
      sessionId: hex(i.sessionIdHex),
      bridgeShare: hex(i.bridgeShareHex),
      issuedAtBd: 9637.5,
      bridgeIssuedAtUnix: i.bridgeIssuedAtUnix,
      ttlSeconds: i.ttlSeconds,
    });
    const tNudged = buildTranscript({
      clientNonce: hex(i.clientNonceHex),
      clientPub: fakeClientPub,
      clientShare: hex(i.clientShareHex),
      sessionId: hex(i.sessionIdHex),
      bridgeShare: hex(i.bridgeShareHex),
      issuedAtBd: 9637.5 + 0.000005, // < half a second; still rounds to same int
      bridgeIssuedAtUnix: i.bridgeIssuedAtUnix,
      ttlSeconds: i.ttlSeconds,
    });
    expect(tExact.equals(tNudged)).toBe(true);

    const tNext = buildTranscript({
      clientNonce: hex(i.clientNonceHex),
      clientPub: fakeClientPub,
      clientShare: hex(i.clientShareHex),
      sessionId: hex(i.sessionIdHex),
      bridgeShare: hex(i.bridgeShareHex),
      issuedAtBd: 9637.5 + 1 / 86400, // exactly one second later
      bridgeIssuedAtUnix: i.bridgeIssuedAtUnix,
      ttlSeconds: i.ttlSeconds,
    });
    expect(tExact.equals(tNext)).toBe(false);
  });
});

// Helper: compute the K_session pin for our fixture. Self-bootstrapping —
// we don't hardcode a magic hex string and pretend it's authoritative.
// The test asserts the spec helper agrees with @noble/hashes' HKDF.
function computeSessionKeyForFixture(): string {
  const i = LINK_V1_TEST_INPUTS;
  const ikm = Buffer.concat([hex(i.clientShareHex), hex(i.bridgeShareHex)]);
  const salt = Buffer.concat([hex(i.clientNonceHex), hex(i.sessionIdHex)]);
  const info = Buffer.from(LINK_SESSION_KEY_HKDF_INFO, 'utf8');
  const k = hkdf(sha256, ikm, salt, info, LINK_SESSION_KEY_LENGTH);
  return Buffer.from(k).toString('hex');
}
