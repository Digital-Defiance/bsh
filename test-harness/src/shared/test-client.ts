/**
 * Minimal EBP/1 client used by tests to talk to mock-brightnexus.
 *
 * This is intentionally tiny — it's not the production client (that's the
 * real `enclave-bridge-client`) and it's not `mock-bsh-client` (which has
 * the full LINK_REGISTER + LINK_DELIVER surface). It exists so
 * tests can send well-formed JSON requests and parse responses without
 * each test recreating socket plumbing.
 *
 * Framing matches EBP/1 §3.2 (brace-terminated). Responses are buffered
 * and dispatched in arrival order to matching pending promises (FIFO).
 */

import { Socket, createConnection } from 'node:net';
import { Buffer } from 'node:buffer';

export class TestClient {
  private socket: Socket | null = null;
  private buffer = Buffer.alloc(0);
  private inflight: Array<{
    resolve: (response: Record<string, unknown>) => void;
    reject: (err: Error) => void;
  }> = [];
  /** Push event handler. Set to receive LINK_PUSH event frames; null otherwise. */
  pushHandler: ((event: Record<string, unknown>) => void) | null = null;

  async connect(socketPath: string): Promise<void> {
    if (this.socket !== null) {
      throw new Error('TestClient already connected');
    }
    this.socket = createConnection(socketPath);
    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error) => {
        this.socket?.removeListener('connect', onConnect);
        reject(err);
      };
      const onConnect = () => {
        this.socket?.removeListener('error', onError);
        resolve();
      };
      this.socket!.once('error', onError);
      this.socket!.once('connect', onConnect);
    });
    this.socket.on('data', (chunk: Buffer) => this.onData(chunk));
    this.socket.on('close', () => this.onClose());
  }

  async disconnect(): Promise<void> {
    const socket = this.socket;
    if (socket === null) return;
    this.socket = null;
    socket.destroy();
    // Drain any inflight requests with a meaningful error.
    while (this.inflight.length > 0) {
      const next = this.inflight.shift()!;
      next.reject(new Error('TestClient disconnected'));
    }
  }

  /**
   * Send a JSON request and await the next JSON response.
   *
   * NOTE: this is FIFO per the EBP/1 §3.4 ordering rule. Tests that issue
   * multiple in-flight requests through a single connection will get
   * responses in send order. LINK_PUSH event frames are *not* responses to
   * any request — they're routed through `pushHandler`.
   */
  async send(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (this.socket === null) throw new Error('TestClient not connected');
    const data = Buffer.from(JSON.stringify(payload));
    return new Promise<Record<string, unknown>>((resolve, reject) => {
      this.inflight.push({ resolve, reject });
      this.socket!.write(data, (err) => {
        if (err) {
          // Pop the just-pushed entry if write failed before any response.
          const idx = this.inflight.findIndex((e) => e.reject === reject);
          if (idx !== -1) this.inflight.splice(idx, 1);
          reject(err);
        }
      });
    });
  }

  private onData(chunk: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (true) {
      const messageEnd = findCompleteJsonObjectEnd(this.buffer);
      if (messageEnd === -1) break;
      const messageBytes = this.buffer.subarray(0, messageEnd + 1);
      this.buffer = this.buffer.subarray(messageEnd + 1);

      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(messageBytes.toString('utf8'));
      } catch (err) {
        // Hand a parse error to the next inflight request; if there isn't
        // one, just drop the bytes (a misbehaving server isn't a test bug).
        const next = this.inflight.shift();
        if (next) next.reject(err as Error);
        continue;
      }

      // Push event detection per RFC §10.2: the bridge emits
      //   {"event":"<event-name>", "counter":<n>, "iv":..., "ciphertext":..., "authTag":...}
      // for LINK_PUSH events. The presence of `iv`+`ciphertext`+`authTag`
      // distinguishes a push frame from any normal request response. The
      // subscribe-ack frame `{ok:true, subscribed:[...]}` does NOT carry
      // those fields and is handled as a normal response below.
      if (
        typeof parsed['event'] === 'string' &&
        typeof parsed['iv'] === 'string' &&
        typeof parsed['ciphertext'] === 'string' &&
        typeof parsed['authTag'] === 'string'
      ) {
        if (this.pushHandler) this.pushHandler(parsed);
        continue;
      }

      const next = this.inflight.shift();
      if (!next) {
        // No request in flight; the server sent us something unexpected.
        // Surface via pushHandler if set, else drop.
        if (this.pushHandler) this.pushHandler(parsed);
        continue;
      }
      next.resolve(parsed);
    }
  }

  private onClose(): void {
    this.socket = null;
    while (this.inflight.length > 0) {
      const next = this.inflight.shift()!;
      next.reject(new Error('Server closed connection'));
    }
  }
}

/** Convenience: produce a fresh, unique socket path under the OS temp dir. */
export function uniqueSocketPath(): string {
  const path = require('node:path') as typeof import('node:path');
  const os = require('node:os') as typeof import('node:os');
  const crypto = require('node:crypto') as typeof import('node:crypto');
  const suffix = crypto.randomBytes(6).toString('hex');
  return path.join(os.tmpdir(), `bn-test-${suffix}.sock`);
}

/**
 * Brace-counting parser per EBP/1 §3.3.
 *
 * Walks `buffer` looking for the end byte of the first complete top-level
 * JSON object, taking string mode and escape sequences into account.
 * Returns the index of that closing brace, or -1 if no complete object yet.
 *
 * This is the spec-mandated client-side parser. The reference server uses a
 * simpler byte-equality match on '}' (§3.2), but client-side responses can
 * legitimately contain nested objects (LIST_KEYS returns an array of key
 * descriptors; METRICS returns `requestCounters: {}`), so the client MUST
 * count braces.
 */
function findCompleteJsonObjectEnd(buffer: Buffer): number {
  // Skip ahead to the next '{' to start.
  let start = -1;
  for (let i = 0; i < buffer.length; i++) {
    if (buffer[i] === 0x7b) { // '{'
      start = i;
      break;
    }
  }
  if (start === -1) return -1;

  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < buffer.length; i++) {
    const byte = buffer[i]!;
    if (inString) {
      if (escaped) {
        // Previous byte was an unescaped backslash inside a string; this
        // byte is the escapee, regardless of what it is.
        escaped = false;
      } else if (byte === 0x5c) { // '\'
        escaped = true;
      } else if (byte === 0x22) { // '"'
        inString = false;
      }
      continue;
    }
    if (byte === 0x22) { // '"' — entering a string
      inString = true;
      continue;
    }
    if (byte === 0x7b) depth++; // '{'
    else if (byte === 0x7d) {   // '}'
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}
