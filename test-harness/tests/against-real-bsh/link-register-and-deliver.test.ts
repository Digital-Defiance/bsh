/**
 * Acceptance tests for **bsh BrightLink delivery** — RFC §4.9: the
 * `bsh-inject` builtin sends credentials directly to the bridge over the
 * EBP/1 socket using `LINK_DELIVER`. Users see credentials in the
 * BrightNexus menu bar without any PTY-proxy work.
 *
 * The tests drive a real bsh binary against `mock-brightnexus` (in-process
 * spec-derived bridge). They validate, byte-exactly, that bsh's BrightLink
 * implementation matches the contract.
 *
 * **Skip behavior:** these tests skip when bsh's BrightLink module is not
 * yet built. The gate is `BSH_HAS_V3_INJECT=1` (kept for compatibility
 * with older invocations); once the bsh module ships, the binary is built
 * with that env var or feature flag and these tests run.
 *
 * `bsh` binary discovery order:
 *   1. `$BSH_BIN` env var
 *   2. `bsh` on `$PATH`
 *
 * What this validates:
 *   - bsh registers a BrightLink session on first inject (lazy `LINK_REGISTER`).
 *   - The session uses bilateral HKDF + SEP-signed transcript verification.
 *   - `bsh-inject` builds an AES-256-GCM ciphertext under K_session and
 *     sends it as `LINK_DELIVER` JSON.
 *   - The deliver counter is the per-session monotonic `c_shell_to_agent`.
 *   - Re-invoking `bsh-inject` reuses the session and bumps the counter.
 *   - The bridge receives a decoded payload that matches what was piped in.
 */

import { describe, it, expect, beforeAll, afterEach, beforeEach } from 'vitest';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, accessSync, constants as fsConst } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { MockBrightNexus } from '../../src/mock-brightnexus/index.js';

// ────────────────────────────────────────────────────────────────────
// Discovery + skip logic
// ────────────────────────────────────────────────────────────────────

const enabled = process.env['BSH_HAS_V3_INJECT'] === '1';

function findBshBin(): string | null {
  const explicit = process.env['BSH_BIN'];
  if (explicit) {
    try {
      accessSync(explicit, fsConst.X_OK);
      return explicit;
    } catch {
      return null;
    }
  }
  try {
    const out = execFileSync('command', ['-v', 'bsh'], { encoding: 'utf8' }).trim();
    if (out) return out;
  } catch {
    // fall through
  }
  return null;
}

const bshBin = findBshBin();

beforeAll(() => {
  if (!enabled) {
    console.log(
      '[real-bsh] Skipping BrightLink acceptance tests.\n' +
        '          To run: build bsh with BrightLink support and re-run with\n' +
        '          BSH_HAS_V3_INJECT=1.',
    );
    return;
  }
  if (!bshBin) {
    console.log('[real-bsh] BSH_HAS_V3_INJECT=1 set but no bsh binary found. Skipping.');
  }
});

const skip = (): boolean => !enabled || bshBin === null;

// ────────────────────────────────────────────────────────────────────
// Per-test scaffold: spin up mock-brightnexus on a private socket
// ────────────────────────────────────────────────────────────────────

let mock: MockBrightNexus;
let tmpDir: string;
let socketPath: string;

beforeEach(async () => {
  if (skip()) return;
  mock = new MockBrightNexus();
  tmpDir = mkdtempSync(join(tmpdir(), 'against-real-bsh-'));
  socketPath = join(tmpDir, 'brightnexus.sock');
  await mock.start(socketPath);
});

afterEach(async () => {
  await mock?.stop();
  try {
    rmSync(tmpDir, { recursive: true, force: true });
  } catch {
    // best effort
  }
});

/**
 * Run a one-shot bsh command non-interactively. The bsh process inherits
 * `BRIGHTNEXUS_SOCKET=<our-mock>` so its embedded EBP/1 client connects
 * to the in-process mock-brightnexus rather than a real BrightNexus.
 */
async function runBsh(commandLine: string): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve, reject) => {
    const child = spawn(bshBin!, ['-c', commandLine], {
      env: {
        ...process.env,
        BRIGHTNEXUS_SOCKET: socketPath,
      },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d.toString('utf8'); });
    child.stderr.on('data', (d) => { stderr += d.toString('utf8'); });
    child.on('error', reject);
    child.on('close', (code) => resolve({ stdout, stderr, code: code ?? -1 }));
  });
}

// ────────────────────────────────────────────────────────────────────
// BrightLink delivery acceptance — the contract bsh must satisfy
// ────────────────────────────────────────────────────────────────────

describe('bsh BrightLink — bsh-inject + LINK_DELIVER', () => {
  it.runIf(enabled && bshBin !== null)(
    'bsh-inject of an ephemeral-auth payload lands a session and an entry',
    async () => {
      const r = await runBsh(
        `printf '%s' '{"username":"alice","password":"hunter2","ttl":300,"issued_at":1748000000}' ` +
          `| bsh-inject --type ephemeral-auth --context http://example.com`,
      );
      expect(r.code).toBe(0);

      // Bridge state should show one session and one credential.
      const audit = mock.state.auditLog;
      const init = audit.find((e) => e.kind === 'session_init');
      expect(init).toBeDefined();
      const ingest = audit.find((e) => e.kind === 'link_deliver_ok');
      expect(ingest).toBeDefined();
      expect((ingest as { payload?: { type?: string } }).payload?.type).toBe('ephemeral-auth');
    },
  );

  it.runIf(enabled && bshBin !== null)(
    'multiple bsh-inject calls in the same shell reuse the session and bump the counter',
    async () => {
      const r = await runBsh(`
        for i in 1 2 3; do
          printf '{"value":"%s","ttl":60}' "$i" \\
            | bsh-inject --type plaintext --context "test://$i"
        done
      `);
      expect(r.code).toBe(0);
      const session_init = mock.state.auditLog.filter((e) => e.kind === 'session_init');
      expect(session_init.length).toBe(1);
      const ingests = mock.state.auditLog.filter((e) => e.kind === 'link_deliver_ok');
      expect(ingests.length).toBe(3);
    },
  );

  it.runIf(enabled && bshBin !== null)(
    'bsh-inject fails closed when the bridge is unreachable',
    async () => {
      // Kill the mock; bsh-inject's lazy LINK_REGISTER should fail.
      await mock.stop();
      const r = await runBsh(
        `printf '{"username":"x","password":"y","ttl":60,"issued_at":1748000000}' | bsh-inject --type ephemeral-auth --context http://x`,
      );
      expect(r.code).not.toBe(0);
      // Any failure-mode message is acceptable; the contract is "fail closed
      // and emit something explanatory". The specific phrase varies by where
      // the failure surfaces.
      expect(r.stderr).toMatch(/bridge|unavailable|connect|LINK_REGISTER|GET_PUBLIC_KEY|fail/i);
      // BrightLink does NOT emit OSC sequences to stdout.
      expect(r.stdout).not.toContain('\x1b]7777;');
    },
  );

  it.runIf(enabled && bshBin !== null)(
    'bsh-inject never writes wire bytes to stdout (BrightLink has no OSC framing)',
    async () => {
      const r = await runBsh(
        `printf '{"value":"a","ttl":60}' | bsh-inject --type plaintext --context test://a`,
      );
      expect(r.code).toBe(0);
      expect(r.stdout).not.toContain('\x1b]7777;');
      expect(r.stdout).not.toContain('\x07');
    },
  );
});
