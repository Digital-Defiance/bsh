/**
 * Bridge socket discovery — implements the order documented in
 * EBP/1 §2.2 / RFC v3 §4.1 / BrightNexus README "Discovery order":
 *
 *   1. ${BRIGHTNEXUS_SOCKET}                  (env override)
 *   2. ${HOME}/.brightchain/brightnexus/brightnexus.sock   (canonical)
 *   3. ${HOME}/.enclave/enclave-bridge.sock                (legacy)
 *
 * Returns the first path that is reachable (stat'able). If none reach,
 * returns `null`. Tests pass an explicit override path; production callers
 * use the discovery order.
 */

import { accessSync, constants } from 'node:fs';

import { EBP1_SOCKET_DISCOVERY_ORDER, EBP1_SOCKET_ENV_VAR } from '../spec/index.js';

export interface DiscoveryArgs {
  /** Override `process.env.HOME`. Defaults to that. */
  home?: string;
  /** Override `process.env.BRIGHTNEXUS_SOCKET`. Defaults to that. */
  envOverride?: string;
  /** Override the candidate list — primarily for testing the discovery
   *  loop itself with paths that are guaranteed to exist/not-exist. */
  candidates?: string[];
}

/** Returns the first reachable socket path from the discovery order, or
 *  null if none are reachable. */
export function discoverSocketPath(args: DiscoveryArgs = {}): string | null {
  const candidates = args.candidates ?? buildDefaultCandidates(args);
  for (const path of candidates) {
    if (path && pathExists(path)) return path;
  }
  return null;
}

/** Returns the full discovery candidate list (in order) — useful for
 *  diagnostics ("the socket you wanted wasn't here, here's where I looked"). */
export function listDiscoveryCandidates(args: DiscoveryArgs = {}): string[] {
  return args.candidates ?? buildDefaultCandidates(args);
}

function buildDefaultCandidates(args: DiscoveryArgs): string[] {
  const home = args.home ?? process.env['HOME'] ?? '';
  const envOverride = args.envOverride ?? process.env[EBP1_SOCKET_ENV_VAR];
  const candidates: string[] = [];
  if (envOverride && envOverride.length > 0) candidates.push(envOverride);
  for (const fn of EBP1_SOCKET_DISCOVERY_ORDER) candidates.push(fn(home));
  return candidates;
}

function pathExists(path: string): boolean {
  try {
    accessSync(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}
