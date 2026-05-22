/**
 * Unix-socket server for `mock-brightnexus`.
 *
 * Implements EBP/1 §3.2 framing (brace-terminator) on the request side and
 * one JSON object per response on the response side. Per-connection state
 * (peer key, BrightLink session, peer attestation) is held in a
 * `ConnectionState` instance.
 *
 * `LINK_PUSH` gets special treatment: instead of being routed through
 * `handleMessage`, the server intercepts it on the connection layer because
 * it requires holding the connection open and emitting multiple JSON frames
 * over the same socket without further reads. The new RFC §10 surface
 * accepts a `subscribe: ["event-name", ...]` array and emits AAD-sealed
 * push frames whenever the underlying engine reports an event of that kind.
 */

import { Buffer } from 'node:buffer';
import { Server, Socket, createServer } from 'node:net';
import { unlinkSync, existsSync } from 'node:fs';
import { createCipheriv } from 'node:crypto';

import {
  EBP1_MESSAGE_TERMINATOR,
  LINK_COMMANDS,
  LINK_PUSH_EVENTS,
  LINK_PUSH_ERRORS,
  LINK_GCM_IV_LENGTH,
  LINK_GCM_TAG_LENGTH,
  buildPushAad,
  type LinkPushEvent,
} from '../spec/index.js';

import {
  BridgeState,
  ConnectionState,
  handleMessage,
} from './handlers.js';
import type { MockBrightNexusOptions } from './types.js';

/** Subscription state for one socket. The bridge keeps one of these per
 *  active push-subscriber connection. */
interface PushSubscription {
  socket: Socket;
  conn: ConnectionState;
  /** Event names this subscriber wants frames for. */
  events: Set<LinkPushEvent | string>;
}

export class MockBrightNexus {
  readonly state: BridgeState;
  private server: Server | null = null;
  private socketPath = '';
  private connections = new Map<Socket, ConnectionState>();
  /** Push subscribers, keyed by session-id hex. */
  private pushSubscribers = new Map<string, PushSubscription[]>();
  /** Cancel handle for the geo-engine zone-transition subscription. */
  private zoneTransitionUnsubscribe: (() => void) | null = null;

  constructor(options: MockBrightNexusOptions = {}) {
    this.state = new BridgeState(options);
  }

  /** Bind and start listening at `socketPath`. Returns when listening. */
  async start(socketPath: string): Promise<void> {
    if (this.server !== null) {
      throw new Error('MockBrightNexus is already started');
    }
    if (existsSync(socketPath)) {
      // Tests are responsible for choosing a unique path; if the file
      // already exists we remove it (mirroring the real BrightNexus
      // SocketServer behavior of `unlink` before `bind`).
      unlinkSync(socketPath);
    }
    this.socketPath = socketPath;

    this.server = createServer((socket) => this.onConnection(socket));

    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject);
      this.server!.listen(socketPath, () => {
        this.server!.removeListener('error', reject);
        resolve();
      });
    });

    // Wire the geo engine's zone-transition stream into our push fan-out.
    // Subscribers will receive AAD-sealed `zone-transition` frames.
    this.zoneTransitionUnsubscribe = this.state.geo.onZoneTransition((event) => {
      this.broadcastZoneTransition(event);
    });
  }

  /** Stop the server and close all connections. */
  async stop(): Promise<void> {
    const server = this.server;
    if (server === null) return;
    this.server = null;

    if (this.zoneTransitionUnsubscribe) {
      this.zoneTransitionUnsubscribe();
      this.zoneTransitionUnsubscribe = null;
    }

    for (const socket of this.connections.keys()) {
      socket.destroy();
    }
    this.connections.clear();
    this.pushSubscribers.clear();

    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
    if (existsSync(this.socketPath)) {
      try {
        unlinkSync(this.socketPath);
      } catch {
        // Best-effort.
      }
    }
  }

  /** Currently bound socket path. Empty string until `start()` resolves. */
  getSocketPath(): string {
    return this.socketPath;
  }

  /** Number of active connections. */
  connectionCount(): number {
    return this.connections.size;
  }

  /** Number of distinct sessions with at least one push subscriber. */
  pushSubscriberCount(): number {
    return this.pushSubscribers.size;
  }

  // ──────────────────────────────────────────────────────────────────────
  // Connection lifecycle
  // ──────────────────────────────────────────────────────────────────────

  private onConnection(socket: Socket): void {
    const conn = new ConnectionState();
    // Pull the peer attestation from the bridge's provider at accept-time.
    // The real bridge does this with kernel introspection; the mock does it
    // by consuming the test's scripted attestation queue.
    conn.attestation = this.state.peerAttestation.attest();
    this.connections.set(socket, conn);

    let buffer = Buffer.alloc(0);

    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (true) {
        const end = buffer.indexOf(EBP1_MESSAGE_TERMINATOR);
        if (end === -1) break;
        const messageBytes = buffer.subarray(0, end + 1);
        buffer = buffer.subarray(end + 1);

        // Intercept LINK_PUSH at the connection layer (it has special
        // multi-frame semantics).
        if (this.tryHandleLinkPush(socket, conn, messageBytes)) {
          continue;
        }

        // Normal request → response. handleMessage is now async to
        // accommodate the geo prompt-resolution flow.
        handleMessage(messageBytes, this.state, conn)
          .then((response) => {
            if (socket.writable) socket.write(response);
          })
          .catch((err) => {
            this.state.recordAudit({
              kind: 'handler_error',
              payload: { message: String(err) },
            });
            if (socket.writable) {
              socket.write(
                Buffer.from(JSON.stringify({ error: 'internal: handler threw' })),
              );
            }
          });
      }
    });

    socket.on('close', () => {
      this.cleanupConnection(socket, conn);
    });
    socket.on('error', (err) => {
      this.state.recordAudit({
        kind: 'connection_error',
        payload: { message: String(err) },
      });
    });
  }

  private cleanupConnection(socket: Socket, conn: ConnectionState): void {
    this.connections.delete(socket);

    if (conn.linkSession) {
      const sidHex = conn.linkSession.sessionId.toString('hex');
      this.state.recordAudit({
        kind: 'session_teardown',
        sessionIdHex: sidHex,
        payload: { reason: 'disconnect' },
      });
      conn.linkSession.kSession.fill(0);
      const subs = this.pushSubscribers.get(sidHex);
      if (subs) {
        const filtered = subs.filter((s) => s.socket !== socket);
        if (filtered.length === 0) {
          this.pushSubscribers.delete(sidHex);
        } else {
          this.pushSubscribers.set(sidHex, filtered);
        }
      }
    }
  }

  // ──────────────────────────────────────────────────────────────────────
  // LINK_PUSH (RFC §10) — intercepted at connection layer
  // ──────────────────────────────────────────────────────────────────────

  /** Returns true if this message was a LINK_PUSH command (handled here);
   *  false to fall through to normal dispatch. */
  private tryHandleLinkPush(
    socket: Socket,
    conn: ConnectionState,
    messageBytes: Buffer,
  ): boolean {
    let req: Record<string, unknown>;
    try {
      req = JSON.parse(messageBytes.toString('utf8'));
    } catch {
      return false;
    }
    if (req['cmd'] !== LINK_COMMANDS.PUSH) return false;

    if (!conn.linkSession) {
      socket.write(
        Buffer.from(JSON.stringify({ error: LINK_PUSH_ERRORS.SESSION_NOT_REGISTERED })),
      );
      return true;
    }

    const subscribeRaw = req['subscribe'];
    if (!Array.isArray(subscribeRaw) || subscribeRaw.length === 0) {
      socket.write(
        Buffer.from(JSON.stringify({ error: LINK_PUSH_ERRORS.UNKNOWN_EVENT_TYPES })),
      );
      return true;
    }

    const requested = subscribeRaw.filter(
      (e): e is string => typeof e === 'string',
    );
    const known: Array<LinkPushEvent | string> = requested.filter((e) =>
      Object.values(LINK_PUSH_EVENTS).includes(e as LinkPushEvent),
    );
    if (known.length === 0) {
      socket.write(
        Buffer.from(JSON.stringify({ error: LINK_PUSH_ERRORS.UNKNOWN_EVENT_TYPES })),
      );
      return true;
    }

    if (conn.pushSubscribed) {
      socket.write(
        Buffer.from(JSON.stringify({ error: LINK_PUSH_ERRORS.SUBSCRIBE_LIMIT })),
      );
      return true;
    }

    conn.pushSubscribed = true;
    const sidHex = conn.linkSession.sessionId.toString('hex');
    const subs = this.pushSubscribers.get(sidHex) ?? [];
    subs.push({ socket, conn, events: new Set(known) });
    this.pushSubscribers.set(sidHex, subs);

    socket.write(
      Buffer.from(JSON.stringify({ ok: true, subscribed: known })),
    );
    return true;
  }

  // ──────────────────────────────────────────────────────────────────────
  // Push fan-out
  // ──────────────────────────────────────────────────────────────────────

  /** Fan a `zone-transition` event out to every subscriber that asked for
   *  it. Each subscriber gets a fresh AAD-sealed frame under their session
   *  key, with the per-session `c_agent_to_shell` counter incremented. */
  private broadcastZoneTransition(event: {
    from: string | null;
    to: string | null;
    atBd: number;
  }): void {
    const body = JSON.stringify({
      from: event.from,
      to: event.to,
      at_bd: event.atBd,
    });
    this.broadcastEvent(LINK_PUSH_EVENTS.ZONE_TRANSITION, Buffer.from(body, 'utf8'));
  }

  /** Fan an event out to every subscriber for that event kind. */
  private broadcastEvent(eventName: LinkPushEvent | string, body: Buffer): void {
    for (const [, subs] of this.pushSubscribers) {
      for (const sub of subs) {
        if (!sub.events.has(eventName)) continue;
        if (!sub.conn.linkSession) continue;
        const session = sub.conn.linkSession;
        session.outboundCounter += 1n;
        const counter = session.outboundCounter;
        const aad = buildPushAad({ counter, event: eventName });
        const iv = this.state.rng(LINK_GCM_IV_LENGTH);
        const cipher = createCipheriv('aes-256-gcm', session.kSession, iv, {
          authTagLength: LINK_GCM_TAG_LENGTH,
        });
        cipher.setAAD(aad);
        const ct = Buffer.concat([cipher.update(body), cipher.final()]);
        const tag = cipher.getAuthTag();
        const frame = Buffer.from(
          JSON.stringify({
            event: eventName,
            counter: Number(counter),
            iv: iv.toString('base64'),
            ciphertext: ct.toString('base64'),
            authTag: tag.toString('base64'),
          }),
        );
        if (sub.socket.writable) {
          sub.socket.write(frame);
        }
      }
    }
  }
}
