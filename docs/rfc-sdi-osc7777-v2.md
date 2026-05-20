# RFC v2: Secure Semantic Data Injection (SDI) via OSC 7777 Escape Sequences

**Author:** Jessica Mulein
**Revised by:** Claude (security review, bidirectional protocol, geographic context integration)
**Status:** Proposal / Draft Standard
**Date:** May 2026
**Forked from:** `rfc-sdi-osc7777.md` (v1, retained for v1-protocol session compatibility).

> **Relationship to v1.** This document is a forked successor to v1, not a patch. v1 remains valid for any deployment that does not require agent-to-shell traffic. v2 introduces (1) a bidirectional envelope so the agent can push sequences to the shell as well as receive them, and (2) a complete `geo-context` payload type with associated zone-policy, helper-CLI, and audit machinery. The cryptographic and protocol-version changes required by bidirectional traffic are baked into §3. v1 and v2 sessions are distinguishable on the wire via the registration handshake (§3.2). New implementations should target v2.

> **Scope.** v2 covers both the SDI transport protocol (§3, §4, §12) and the geographic context extension (§5–§11). These were two documents in earlier drafts and have been combined here so a reader sees one coherent specification with intra-document cross-references.

---

## 1. Abstract

Modern terminal workflows routinely interact with, generate, and process multi-field, highly structured ephemeral data—such as dynamic test credentials, cloud session authentication elements, and complex infrastructure connection contexts.

However, the protocol layer interfacing terminal emulator tasks with the host operating system remains restricted to flat text streaming or unsecured, single-value system clipboards. This document proposes an open, cross-platform standard for Secure Semantic Data Injection (SDI) using a new operating system command sequence (OSC 7777), enabling isolated, cryptographically validated pipeline structures to communicate typed JSON states natively between shells and background companion applications without risking clipboard exposure or text-forgery attacks.

---

## 2. The Problem & The Vulnerability Vector

### 2.1 Limitations of the System Clipboard

Passing rich structural schemas (such as a username, password, and seed phrase simultaneously) via the native OS clipboard forces an unideal developer compromise: either concatenating strings into fragile formats, manually copying individual fields iteratively, or leaking sensitive credentials to local background clipboard manager histories.

### 2.2 Terminal Line Hijacking & Rogue Code Execution

Relying on standard unauthenticated Operating System Commands (OSC) to communicate with native desktop applications poses a severe security hazard. If a terminal environment blindly parses and acts upon plaintext escape sequences embedded within standard output, any untrusted asset—such as a malicious repository file evaluated via `cat`, a deceptive git commit log, or an unvetted server Message of the Day (MOTD)—can forge sequences to inject structural data or trigger unintended desktop-agent side-effects.

---

## 3. Architecture Specification

The Secure SDI standard introduces a distinct decoupled separation between the Transport Vector (the PTY text pipeline) and the Authentication Control Layer (an out-of-band IPC handshake).

### 3.1 Out-of-Band Cryptographic Registration

Before any data injection takes place, an interactive shell session registers itself with a localized, user-restricted background Desktop Agent Daemon running on the host system.

1. **Local Channel:** The Agent hosts a restricted Unix domain socket accessible exclusively by the local user account (`chmod 600`, `stat.st_uid == getuid()`). The socket path **must** include a per-boot or per-agent random component (e.g. `/run/user/<uid>/sdi-agent-<16-random-hex>.sock`) to prevent socket-path squatting by a malicious process that starts before the agent. The socket path is communicated to child shells via a protected environment variable (`SDI_AGENT_SOCK`) set only at agent startup.

2. **Ephemeral Exchange:** The shell instance connects to the socket during its initialization phase and performs an X25519 ECDH key agreement followed by HKDF-SHA256 derivation to produce a unique 32-byte session key ($K_{session}$) alongside a transient Session-ID.

3. This key resides strictly within the active memory space of that specific shell process and the Desktop Agent.

4. **Session Expiry:** Sessions have a maximum lifetime of 8 hours regardless of activity. The agent **must** refuse to decrypt OSC 7777 sequences for expired sessions and **must** log the attempt. Shells that outlive their session must re-register.

5. **Squatting Defense:** On startup the agent **must** verify that no file exists at the chosen socket path before binding. If a socket file already exists at that path, the agent **must** abort with a fatal error rather than overwriting it.

### 3.2 Registration Wire Protocol

The registration handshake uses a compact binary framing over the Unix domain socket — **no JSON, no length prefix**.

**Shell → Agent** (49 bytes, sent atomically):

| Offset | Length | Content |
| --- | --- | --- |
| 0 | 1 | `protocol_version` — `0x02` for this RFC. v1 sends `0x01`. |
| 1 | 16 | `session_id` — 16 cryptographically random bytes generated by the shell |
| 17 | 32 | `shell_pub` — the shell's ephemeral X25519 public key (raw 32-byte little-endian) |

**Agent → Shell** (33 bytes):

| Offset | Length | Content |
| --- | --- | --- |
| 0 | 1 | `protocol_version` — agent echoes the version it agrees to speak (`0x02`); the agent MAY refuse a `0x01` shell by closing the connection without responding. |
| 1 | 32 | `agent_pub` — the agent's ephemeral X25519 public key (raw 32-byte little-endian) |

After the exchange both sides independently derive the session key:

$$K_{session} = \text{HKDF-SHA256}(\text{IKM} = X25519(\text{priv}, \text{peer\_pub}),\ \text{salt} = \text{session\_id},\ \text{info} = \text{"sdi-session-key-v2"},\ L = 32)$$

The HKDF `info` string is `"sdi-session-key-v2"` for v2, distinguishing v2 keys from v1 (`"sdi-session-key"`). This ensures even an accidental version mismatch produces incompatible keys rather than silent cross-version traffic.

The socket connection is then closed. $K_{session}$ is never transmitted.

**Mixed-version sessions are not supported.** A v2 agent receiving `0x01` MUST close the connection without responding (and SHOULD log). A v1 agent receiving `0x02` will read the version byte as part of `session_id` and the handshake will fail at HKDF derivation; this is acceptable as a degenerate-fail mode but v2 shells SHOULD detect v1 agents by other means (e.g. agent advertising its version in the path-file or environment) before attempting registration.

**Session-ID encoding:** The raw 16-byte `session_id` is encoded as 32 lowercase hex characters in the OSC sequence (e.g. `2a3f...`).

**Rate limiting:** The agent **must** enforce a rate limit of no more than 10 failed authentication attempts per minute per connecting PID. Exceeding this threshold causes the agent to close the connection and log a warning. This mitigates local brute-force enumeration of session IDs.

### 3.3 The Secure OSC 7777 Sequence Syntax

In v2, OSC 7777 sequences flow in both directions over the same encrypted envelope:

- **Shell → Agent.** The shell or any utility within it emits sequences via stdout/`/dev/tty`; the terminal emulator forwards them to the agent.
- **Agent → Shell.** The agent emits sequences directly to the shell's PTY (the agent has the PTY descriptor from registration metadata, or pushes through a registered terminal-emulator API). The shell reads them from its terminal input stream.

The wire encoding is identical in both directions. Direction is bound into the AAD (§3.4) so cross-direction replay is impossible even with a key compromise that allows decryption.

When a utility or process inside the shell wants to broadcast structured semantic data, or when the agent wants to push state to a registered shell, the sender wraps the payload in an encrypted OSC 7777 macro structure:

```
\e]7777;<session-id-hex>;<base64-counter>;<type>;<base64-context>;<base64-nonce>;<base64-ciphertext>;<base64-auth-tag>\a
```

| Field | Encoding | Description |
| --- | --- | --- |
| `session-id-hex` | 32-char lowercase hex | Maps the sequence to a registered session key |
| `base64-counter` | standard Base64 | 8-byte big-endian unsigned monotonic sequence counter (per direction; see §3.5) |
| `type` | plaintext ASCII | Payload schema identifier (e.g. `ephemeral-auth`, `geo-context`) |
| `base64-context` | standard Base64 | Routing context (e.g. API URL); Base64 to avoid semicolon collisions |
| `base64-nonce` | standard Base64 | 12-byte AES-GCM initialization vector |
| `base64-ciphertext` | standard Base64 | AES-256-GCM encrypted JSON payload |
| `base64-auth-tag` | standard Base64 | 16-byte GCM authentication tag |

`\a` (BEL, 0x07) is the sequence terminator.

**Direction is not encoded on the wire.** It is determined by the receiver: a sequence read from stdin/PTY input is `Agent → Shell` (`dir_tag = 0x02`); a sequence read from PTY stdout by the agent is `Shell → Agent` (`dir_tag = 0x01`). The receiver knows which direction it is reading and uses the corresponding `dir_tag` for AAD reconstruction during decryption. An attacker replaying a captured sequence cannot move it between directions because the receiver always uses its own direction tag, and a tag mismatch causes GCM authentication to fail.

> **Note on `type` field confidentiality:** The `type` field is transmitted in plaintext and will be visible to any observer of the PTY stream (e.g. terminal recordings, log captures). Implementations that consider the payload schema identifier sensitive **should** use a generic `type` value (e.g. `sdi-payload`) and encode the true type inside the encrypted JSON body. See §4 for schema conventions.

### 3.4 Additional Authenticated Data (AAD)

The `dir_tag`, `counter`, `type`, and `context` values are bound into the AES-256-GCM authentication tag as Additional Authenticated Data. The AAD **must** be constructed using length-prefixed encoding to prevent boundary confusion attacks:

$$\text{AAD} = \text{LE32}(1) \mathbin\| \mathit{dir\_tag} \mathbin\| \text{LE32}(\text{len}(\mathit{counter\_bytes})) \mathbin\| \mathit{counter\_bytes} \mathbin\| \text{LE32}(\text{len}(\mathit{type\_bytes})) \mathbin\| \mathit{type\_bytes} \mathbin\| \text{LE32}(\text{len}(\mathit{context\_bytes})) \mathbin\| \mathit{context\_bytes}$$

where:

- `LE32(n)` is a 4-byte little-endian encoding of `n`.
- `dir_tag` is a single byte: `0x01` for Shell → Agent, `0x02` for Agent → Shell. The leading `LE32(1)` is the length prefix of the `dir_tag` field, kept for symmetry with the rest of the length-prefixed scheme.
- `counter_bytes` is the raw 8-byte big-endian counter from the appropriate direction (see §3.5).
- `type_bytes` is the UTF-8 encoding of the type string.
- `context_bytes` is the raw decoded bytes of the Base64 context field.

The receiver supplies all four values during decryption. If `type` or `context` is absent from the wire (legitimately empty fields are not currently defined, but the construction tolerates them), its length prefix is `LE32(0)` and it contributes zero payload bytes (the length prefix itself is still included). `dir_tag` and `counter_bytes` are never absent.

This construction ensures that a captured ciphertext cannot be replayed under a different direction, type, context, or counter value even if the session key were somehow extracted.

### 3.5 Replay Protection via Per-Direction Monotonic Counters

Each session maintains **two** independent monotonic counters, one per direction:

- `c_shell_to_agent` — incremented by the shell on every emit; validated by the agent on receive.
- `c_agent_to_shell` — incremented by the agent on every emit; validated by the shell on receive.

Both initialize to `0` at registration. The wire encoding (8-byte big-endian unsigned, base64) is unchanged from v1; only the per-side bookkeeping splits.

Each side MUST track:

1. Its own outbound counter for the direction it emits in (used to fill `counter_bytes` on emit, incremented by 1 per emit).
2. The highest accepted counter for the direction it receives from (used for replay-window validation).

On receipt, the receiver:

- Reconstructs AAD using its receiving direction's `dir_tag` (§3.4).
- Verifies the GCM authentication tag.
- If verification succeeds, applies the replay window: accepts counters in `(last_accepted + 0, last_accepted + 1000]` (i.e. strictly greater than `last_accepted`, up to a tolerance of 1000 to allow out-of-order delivery in pipelines). Rejects any counter at or below `last_accepted`, or beyond the window.
- Logs all replayed or out-of-window counter values as security events.

Because direction is bound into AAD, a captured Shell→Agent sequence cannot be replayed as Agent→Shell or vice versa: GCM tag verification fails on the wrong-direction reconstruction. The two counter namespaces are therefore independent and never collide.

This prevents replay of any captured OSC 7777 sequence in either direction, even within an active session.

### 3.6 Injection Interface

The reference shell (`bsh`) exposes a builtin `bsh-inject` that implements the full encrypt-and-emit pipeline:

```
bsh-inject --type <type> --context <url>
```

The JSON payload is read from **stdin**. The builtin performs lazy session initialisation (if not already registered), increments the session counter, encrypts with $K_{session}$, and writes the OSC 7777 sequence **directly to `/dev/tty`** rather than stdout. This ensures the sequence reaches the terminal emulator regardless of how the caller has redirected stdout, and prevents the ciphertext from being accidentally written to files, pipes, or logs.

If stdout emission is explicitly required (e.g. for testing or piping to a custom terminal), the flag `--emit-stdout` may be passed to override this behavior. Callers using `--emit-stdout` are responsible for ensuring the sequence reaches a terminal emulator and not a log sink.

**Agent failure behavior:** If the agent is unavailable or the session has not been registered, `bsh-inject` **must** fail closed — it prints an error to stderr and exits non-zero. It **must not** fall back to emitting plaintext or unencrypted OSC sequences.

---

## 4. Standardized Payload Schemas

To maintain universal compatibility across browser extensions, form fillers, and desktop application management panels, payloads must adhere to predictable, strongly-typed semantic JSON specifications.

### 4.1 ephemeral-auth

Targeted at seeding short-lived accounts, hotseat multiplayer testing matrices, and web environment login flows.

```json
{
  "type": "ephemeral-auth",
  "context": "http://localhost:3005",
  "ttl": 300,
  "issued_at": 1748000000,
  "data": {
    "username": "player1",
    "password": "TemporarySecurePassword123!",
    "email": "player1@localhost.localdomain",
    "additional_fields": {
      "mnemonic": "fury appear bargain good coin load tattoo object convince render soft inside..."
    }
  }
}
```

### 4.2 db-connection

Targeted at dynamically focusing or pre-configuring native desktop graphic database viewers straight from an active terminal workspace context.

```json
{
  "type": "db-connection",
  "context": "development-cluster-alpha",
  "ttl": 60,
  "issued_at": 1748000000,
  "data": {
    "engine": "postgresql",
    "host": "127.0.0.1",
    "port": 5432,
    "user": "db_admin",
    "pass": "ephemeral_token_string"
  }
}
```

**Schema notes:**

- The `issued_at` field (Unix timestamp, seconds) is **required** in all payload schemas. Agents **should** reject payloads whose `issued_at` is more than `ttl` seconds in the past, or more than 60 seconds in the future, as an additional defense-in-depth layer against replayed payloads that bypass counter validation.
- The `ttl` field specifies the maximum lifetime of the decrypted state in the agent's memory. Agents **must** purge decrypted state after `ttl` seconds regardless of other conditions.

### 4.3 geo-context

A bidirectional payload type carrying location fixes from the agent (push, on zone transitions and `command_jit` triggers) and queries / acknowledgements from the shell. Unlike `ephemeral-auth` and `db-connection`, `geo-context` introduces additional machinery — zone definitions, an authorization socket for child processes, advisory pre-exec semantics, and audit logging — defined in §5 through §9 of this document. The full plaintext schema, the JSON wire format, and the failure-payload structure are specified in §5.

`geo-context` uses BrightDate scalars for timestamps (not Unix epoch), exposes coordinates in three forms (geodetic / BrightSpace ECEF / BrightSpaceTime) with the geodetic form treated as the canonical input from the host OS, and is the first SDI payload type to require agent-to-shell pushes — i.e. the first user of the bidirectional envelope (§3.3).

---

## 5. Threat Model and Enforcement Tiers (Geographic Context)

This section covers threats specific to the `geo-context` payload type. SDI transport-layer threats are covered in §10.

### 5.1 Tiers

The geographic context spec uses a two-tier model. v2 normatively defines **Tier 1 only.**

| Tier | What it provides | Where enforcement lives |
| --- | --- | --- |
| **Tier 1 — Advisory (this RFC)** | Friction against accidental misuse, audit trail, automation hooks, location-aware shell ergonomics. | Bsh + SDIAgent, user-space. |
| **Tier 2 — Authoritative (Appendix C, informational)** | Actual prevention of `execve`. | Privileged `EndpointSecurity` (macOS) / eBPF LSM (Linux) daemon, sharing this RFC's policy file format. |

### 5.2 Adversaries In Scope (Tier 1)

- **Tampered terminal stream.** A captured/forged OSC 7777 sequence in stdout (e.g. from `cat` of a hostile file). Defended by the AES-256-GCM authentication tag (§3) plus the bidirectional counter and AAD direction tag (§3.4–§3.5).
- **Sensor-source spoofing of zone transitions on the wire.** Defended cryptographically by the encrypted SDI envelope.
- **Cross-process leakage of location data.** Defended by the agent-as-keyserver model of §6: coordinates never enter `environ`, never enter argv, never enter history.
- **Replay of captured `geo-context` sequences.** Defended by the per-direction monotonic counters (§3.5) and the BrightDate `issued_at`/`expires_at` window.
- **NTP rollback to resurrect expired payloads.** Defended by monotonic-clock-backed expiry on the agent side.

### 5.3 Adversaries Out of Scope (Tier 1)

The following are **not** defended against by this RFC. Implementors and documentation MUST NOT imply otherwise.

- The user themselves on their own machine.
- Malicious code already executing in the user's session under the user's UID.
- A user running a different shell, copying a binary, executing inside a container/VM, or booting another OS.
- OS-level compromise (kernel, signed-kext, system-level location-service tampering).
- Sensor-level spoofing (GPS spoofing, Wi-Fi BSSID spoofing). The agent receives whatever the OS reports; this RFC does not introduce a sensor-integrity layer beyond the `provenance` field which records the OS's own classification.

The intent of Tier 1 is *automation and audit*, not *access control*. §9 states this in plain language.

---

## 6. The `geo-context` Payload — Schema and Bidirectional Use

`geo-context` is an SDI payload type that flows in **either direction** over the OSC 7777 envelope, encrypted under `K_session` per §3. It is the first user of the bidirectional envelope and the only payload defined in this RFC that requires it.

### 6.1 Why Bidirectional

- **Shell → Agent.** Bsh emits queries, acknowledgements, and audit events.
- **Agent → Shell.** The agent pushes location updates on zone transitions (§7) and `command_jit` triggers (§8).

The cryptographic envelope, AAD construction (§3.4), per-direction counters (§3.5), and direction-determination rules (§3.3) apply unchanged.

### 6.2 Plaintext Payload Schema (Success)

The plaintext (post-decryption) payload is JSON. The wire format mirrors the Rust struct names from `brightdate::geodesy` and `brightdate::relativity` so a Rust consumer MAY deserialize the relevant blocks directly.

```json
{
  "type": "geo-context",
  "context": "system-gps",
  "issued_at_bd": 9626.531421,
  "expires_at_bd": 9626.534893,
  "ttl_seconds": 300,

  "zones_entered": ["office"],
  "zones_exited":  [],

  "geodetic":  { "latitude": 47.3073, "longitude": -122.2285, "altitude": 64.2 },
  "ecef":      { "x": -2294592.1, "y": -3624318.9, "z": 4665842.4 },
  "spacetime": { "t": 831492283.7, "x": -7.6541e-3, "y": -1.2095e-2, "z": 1.5568e-2 },

  "altitude_assumed": false,

  "accuracy_metres": 15.0,
  "provenance": "hardware",
  "user_presence": true
}
```

**Field-by-field:**

| Field | Type | Units | Notes |
| --- | --- | --- | --- |
| `issued_at_bd` | f64 | BrightDate days since J2000.0 | Set by the agent at emit time using its monotonic clock. Authoritative absolute timestamp for audit/log consumers. |
| `expires_at_bd` | f64 | BrightDate days since J2000.0 | Agent stops accepting / serving this fix after this instant. |
| `ttl_seconds` | u32 | SI seconds | Convenience; equals `(expires_at_bd − issued_at_bd) × SECONDS_PER_DAY`. |
| `zones_entered` / `zones_exited` | array of string | — | Names of zones the user transitioned into/out of since the previous fix. Empty array if no transition. Zone names are matched against `~/.config/bsh/geo-zones` (§7.1). |
| `geodetic.latitude` / `.longitude` / `.altitude` | f64 | degrees, degrees, metres (WGS84 ellipsoidal) | Mirrors `brightdate::geodesy::GeodeticCoordinate`. `altitude` MAY be `null` when the OS does not report altitude. |
| `ecef.x` / `.y` / `.z` | f64 | metres | Mirrors `brightdate::geodesy::EcefCoordinate`. Computed from `geodetic` via `geodetic_to_ecef`. |
| `spacetime.t` | f64 | **Bright-Seconds since J2000.0** | Equals `issued_at_bd × SECONDS_PER_DAY`. Mirrors the `t` field of `brightdate::relativity::SpacetimeEvent`. |
| `spacetime.x` / `.y` / `.z` | f64 | **BrightMeters** | Computed as `ecef.{x,y,z} / BRIGHT_METER_M`. Mirrors `SpacetimeEvent.{x,y,z}`. Earth-scale ECEF compresses to small fractions of a BrightMeter; this is correct and intentional for c=1 work. |
| `altitude_assumed` | bool | — | `true` iff the OS did not report altitude and the agent substituted `altitude = 0` (WGS84 ellipsoid surface) before computing `ecef` and `spacetime`. Consumers that care about Z accuracy MUST inspect this. |
| `accuracy_metres` | f64 | metres | Horizontal accuracy as reported by the OS. |
| `provenance` | enum | — | `"hardware"` (GPS/Cellular) or `"network"` (Wi-Fi/IP heuristics). |
| `user_presence` | bool | — | `true` if the agent verified active user presence (biometric API or strict idle-time check) during this fix; `false` otherwise. See §8.3. |

**Canonical input.** The agent receives geodetic from the host OS location service and treats it as authoritative. `ecef` and `spacetime` are derived views computed by the agent using `brightdate::geodesy::geodetic_to_ecef` (Bowring 1985 closed-form). They MUST NOT be considered independent measurements.

**Single source of truth.** All consumers of a given fix see identical numbers across all three blocks. Bsh and `bsh-geo` are pure transport; the conversion happens once, in the agent.

### 6.3 Plaintext Payload Schema (Failure)

```json
{
  "type": "geo-context",
  "context": "system-gps",
  "issued_at_bd": 9626.531421,
  "expires_at_bd": 9626.531594,
  "error": "denied"
}
```

Failure payloads carry `expires_at_bd` (matching the success schema) so consumers know when a retry would be reasonable. A failure payload is itself short-lived: agents SHOULD set `expires_at_bd` to roughly 15 seconds out from `issued_at_bd` so that callers retrying a failed acquisition do not hammer the agent within that window.

`error` values:

| Value | Meaning |
| --- | --- |
| `"denied"` | The OS-level authorization (Location Services / equivalent) denied the request. |
| `"unavailable"` | Hardware/network sensor returned no fix within the configured wait window. |
| `"expired"` | A consumer requested a fix that the agent had already aged out. (Used in §8 query replies; not pushed.) |
| `"presence_failed"` | The fix was acquired but `require_presence` was set and presence verification failed. |

A failure payload received over the push channel MUST cause bsh to assume the `OUTSIDE` state for all currently-defined zones, fail-closed for any in-flight `command_jit` check, and not block waiting for a TTL timeout.

---

## 7. Zone Definitions and Transitions

### 7.1 Zone File: `~/.config/bsh/geo-zones`

Zones are user-defined and user-owned. There is no `/etc/` system-wide zone file — see §9 for the rationale.

```
# zone_name  latitude,longitude  radius_metres  [options]
office       47.6062,-122.3321  120  hardware
home         47.7000,-122.2000  150
datacenter   47.3073,-122.2285   25  hardware,presence
```

**Format:**

- One zone per line. Whitespace-separated. Lines beginning with `#` are comments.
- `zone_name`: ASCII identifier, `[a-z][a-z0-9_-]*`, max 64 chars.
- `latitude,longitude`: WGS84 decimal degrees, ASCII period decimal separator, no thousands separator. Range checked: lat ∈ [−90, 90], lon ∈ [−180, 180].
- `radius_metres`: positive f64, ASCII period decimal separator. Practical range [1, 1e6].
- `options` (optional, comma-separated):
  - `hardware`: zone match requires `provenance == "hardware"`. Network-only fixes are treated as outside.
  - `presence`: zone match requires `user_presence == true` at fix time.

**Permissions.** The agent MUST refuse to honor `~/.config/bsh/geo-zones` if it is group- or world-writable, or if its owner UID does not match the agent's effective UID. On refusal the agent logs a warning and serves no zones.

**Reload.** The agent reloads the zone file on `SIGHUP` and on detected file modification. Reload is atomic: a malformed file leaves the previous zone set active and logs a parse error.

**File-state matrix.** The agent's response to each zone-file state:

| File state | Loaded zones | Agent log level | Effect on shells |
| --- | --- | --- | --- |
| Absent | None | info, once at startup | No zone matches; `command_jit` refusals proceed with `zone='none'`. |
| Present, permissions OK, well-formed, ≥1 zone | Parsed set | info | Normal operation. |
| Present, permissions OK, well-formed, empty (or all comments) | None | info | Same as absent. |
| Present, permissions OK, malformed | Previous set retained (or none if first load) | error | `command_jit` continues against last good set; reload retried on next SIGHUP/modification. |
| Present, group/world-writable, or wrong owner | None | warning | Treated as absent; user is notified once via OSC 7777 push (`type: "sdi-config-error"`) so they can fix the perms. |

**Matching.** The agent does the matching. Bsh receives only zone *names*. Bsh never sees the geometry of zones the user is currently outside of. (This limits the blast radius of a bsh-side compromise: an attacker learns the names of zones the user has visited in this session, not the full set of definitions.)

**Example file.** A starter zone file SHOULD ship at `<install_prefix>/share/bsh/examples/geo-zones.example` containing two or three commented-out sample zones. Users copy it to `~/.config/bsh/geo-zones`, edit, and `chmod 0600`.

### 7.2 Transition Events

The agent emits a `geo-context` push on the OSC 7777 channel whenever:

- The user enters or exits any defined zone.
- A `command_jit` trigger (§8) is fired by bsh.
- Manually requested via the agent's IPC interface (e.g., `bsh-geo --refresh`).

The push contains the full §6.2 payload. `zones_entered` and `zones_exited` enumerate the deltas since the previous emitted fix on this session.

### 7.3 Shell-Side Surface

Bsh exposes the following when `setopt BSH_GEO` is enabled:

| Symbol | Type | Notes |
| --- | --- | --- |
| `$BSH_GEO_ZONE` | string | Current matched zone (newest entered). Empty if not in any zone. **Not exported** by default (`typeset -g`, not `typeset -gx`). |
| `$BSH_GEO_ZONES` | array | All zones currently matched. **Not exported** by default. |
| `$BSH_GEO_PROVENANCE` | string | `"hardware"`, `"network"`, or empty. Not exported. |
| `$BSH_GEO_SOCK` | string | Path to the agent's geo query socket. **Exported** (this is the only geo data deliberately exposed to children, and it is just a socket path, not coordinates). See §8. |
| `bsh_geo_enter_<zone>` | function | If defined, called when `<zone>` is entered. Same dispatch model as `chpwd_functions`. |
| `bsh_geo_exit_<zone>` | function | If defined, called when `<zone>` is exited. |
| `~/.config/bsh/geo-triggers.d/*` | scripts | If executable, run on every transition. See §7.4. |

When `BSH_GEO` is not set, none of the above are populated; the geo socket is not announced to children; OSC 7777 `geo-context` pushes are silently dropped at the bsh side.

### 7.4 Trigger Scripts

Files in `~/.config/bsh/geo-triggers.d/` that are executable and match the pattern `[a-zA-Z0-9._-]+` (no leading dot beyond extensions) are invoked by bsh on every zone transition.

**Invocation:**

- Run as the user, never as root. There is no `/etc/` variant.
- A sanitized environment: only `PATH`, `HOME`, `USER`, `LANG`, `LC_*`, and `BSH_GEO_SOCK` are passed. The script can pull coordinates via `BSH_GEO_SOCK` if it is allowlisted (§8).
- Transition data is provided on **stdin** as a single JSON line:
  ```json
  {"event":"enter","zone":"office","provenance":"hardware","issued_at_bd":9626.531421}
  ```
  or
  ```json
  {"event":"exit","zone":"office","provenance":"hardware","issued_at_bd":9626.531421}
  ```
- argv carries no transition data (argv is `ps`-visible).
- Lat/lon are NOT passed to trigger scripts directly. Scripts that need coordinates use the `bsh-geo` helper, which subjects them to the allowlist check.
- Script execution timeout: 5 seconds. Hard kill on timeout. Log on timeout.
- One trigger script's failure does not affect others.

---

### 7.5 Advisory Pre-Exec Semantics and Overrides

This section is normative for Tier 1 implementations. It defines exactly what bsh does when a `command_jit`-fenced command is invoked outside its zone.

#### 7.5.1 Goals

The advisory check exists for one purpose: **catch honest mistakes loudly enough to be useful, with an audit trail strong enough to be reviewable, while never claiming to enforce.** A v2 implementation that prints "blocked" without an override path is annoying; one that silently allows is useless; one that pretends to enforce is dishonest.

#### 7.5.2 Required Behaviour

When bsh is about to execute a command that matches a `command_jit` rule and the current `geo-context` indicates the command is fenced and the user is outside its zone:

1. Bsh **MUST NOT** execute the command directly.
2. Bsh **MUST** print an advisory message to stderr in the form specified in §7.5.3.
3. Bsh **MUST** emit an audit event to the agent over the persistent SDI session (encrypted via `K_session`, with `dir_tag = 0x01` shell→agent, and with `type` set to `sdi-audit`). The payload schema is `{"kind":"advisory_refusal","command":...,"argv":[...],"zone_name":...,"distance_metres":...,"accuracy_metres":...,"provenance":...,"issued_at_bd":...}`. See §8.3 for what the agent records.
4. Bsh **MUST** return exit code `124`. (Rationale: avoids the POSIX `EX_NOPERM` 77 collision and the 126/127 shell-builtin collisions; sits in the unused 120–125 range.)
5. Bsh **MUST NOT** propose any flag, alias, or syntax that pretends to override at the level of the fenced command itself. The override is invoked through `bsh-geo-override` (§7.5.4).

#### 7.5.3 Required Advisory Format

The stderr message MUST contain, in order:

```
bsh: advisory: '<command>' is fenced to zone '<zone>'.
     Current location: <distance_metres>m from zone, <accuracy>m accuracy, provenance=<provenance>.
     This is a Tier 1 advisory check, not enforcement; see Appendix C.
     To proceed in this shell:
         bsh-geo-override --reason "<your reason>" -- <command> <args>...
     To run without geo-aware checks at all, invoke through any non-bsh shell.
```

The "see Appendix C" line is required honesty. The "any non-bsh shell" line is also required honesty: a user who reads the message learns immediately that the friction is at the bsh layer only. Hiding this would be deceptive given the threat model in §5.3.

The exact wording above is a SHOULD; implementations MAY rephrase for localization but MUST preserve all four elements (zone identification, current location summary, advisory disclaimer, override syntax) and MUST mention the non-bsh-shell escape.

#### 7.5.4 The `bsh-geo-override` Helper

Shipped alongside `bsh-geo`. Syntax:

```
bsh-geo-override [--reason "<text>"] -- <command> <args>...
```

Behaviour:

1. Allowlist check: `bsh-geo-override` MUST itself appear in `~/.config/bsh/geo-allow`. Without this it cannot read the geo-context for the audit log.
2. Read the current `geo-context` from the agent (via the geo socket, §6).
3. Emit an audit event to the agent with kind `advisory_override`. The event MUST include: the user-supplied `--reason` text (or empty string if absent), the resolved absolute path of `<command>` (via `realpath`, see §6.4), full argv, the active zone(s) at override time, distance from the rule's fenced zone, accuracy, and provenance.
4. `execve` `<command>` with its argv. **No further bsh involvement.** The override helper itself is not a long-running supervisor; once exec'd, the command's exit code becomes the override's exit code.

`bsh-geo-override` is **not** a privilege boundary. A malicious script that knows the override syntax can use it to bypass the advisory check. That is acceptable: per §5.3, this RFC does not defend against malicious code in the user's session. The override exists for the user's own convenience and for audit; it is not gating anything that matters.

#### 7.5.5 `--reason` Conventions

The `--reason` flag is technically optional, but `bsh-geo-override` SHOULD prompt interactively if it is missing and the standard input is a TTY:

```
$ bsh-geo-override -- kubectl-prod delete deployment/checkout
Override reason (one line): emergency rollback, on-call PagerDuty PD-12345
```

Reasons are free-form strings, capped at 280 characters by the agent (longer reasons are truncated and a flag is set in the audit entry). They are stored verbatim in the in-memory audit log; they MUST NOT be parsed for structure by the agent or bsh.

If neither the flag is supplied nor stdin is a TTY (e.g., the override is invoked from a script), the reason field is recorded as the empty string. The audit entry's `reason_supplied` boolean reflects this distinction.

#### 7.5.6 What This Buys You

After a month of use, `bsh-geo --audit overrides` (per §8.3) can answer:

- Which fenced commands are routinely overridden, and for what reasons → those probably shouldn't be fenced; the rule is wrong.
- Which fenced commands are rarely overridden → those rules are doing what they should.
- Which user habits trigger advisory refusals → maybe the user needs a different zone defined.

The friction itself is not the win. The data the friction generates is the win.

---

## 8. Coordinate Access for Child Processes

This section defines how a process other than bsh itself (e.g. an `iputils` helper, a deploy script, a weather utility) reads the current location.

### 8.1 Design Constraints

The data has properties that rule out the obvious approaches:

- **Cannot live in environment variables.** Children inherit indefinitely, the value cannot be revoked from already-running processes, TTL becomes a polite suggestion. Leaks into Docker/CI/sudo. Visible to *every* descendant rather than the specific consumer.
- **Cannot live in a file.** Files are readable by anything sharing the UID, persist past TTL, leave a trail.
- **Cannot live in argv.** History, `ps`, audit-log capture.

The only shape that gives real TTL, real per-program authorization, and zero ambient broadcast is **agent-as-keyserver**: a Unix-domain socket that authenticated peers query per-invocation.

### 8.2 The Geo Query Socket

Distinct from the SDI registration socket of §3.1. The agent uses **two-level path indirection** so that long-running clients survive an agent restart:

| Name | Path | Mode | Contents |
| --- | --- | --- | --- |
| **Path file** | `/run/user/<uid>/sdi-agent.geo.path` | `0600`, owner UID | A single line: the absolute path of the live socket. Stable name across restarts. |
| **Socket** | `/run/user/<uid>/sdi-agent-<random>.geo.sock` | `0600`, owner UID | The actual Unix-domain socket. Random component preserves the squat-resistance property of §3.1. |

Agent startup:

1. Generate random component, choose socket path.
2. Verify no file exists at that socket path; fatal-abort if it does (squat defense, §3.1).
3. Bind socket.
4. Atomically write the new socket path into `<...>.geo.path` via `write` to a tempfile + `fsync` + `rename`.

Agent shutdown:

5. Unlink socket and path file. (On crash these may persist; clients MUST be tolerant of stale path-file contents.)

`$BSH_GEO_SOCK` exported by bsh contains the **path-file path**, not the socket path. Clients (`bsh-geo` and any other) follow this protocol per request:

1. Open and read `$BSH_GEO_SOCK` (the path file). Extract the socket path.
2. Connect to the socket path.
3. On `ECONNREFUSED` / `ENOENT`, re-read the path file (the agent may have restarted) and retry once. After a second failure, return error code 2 (agent unreachable).

This means a long-running process whose `BSH_GEO_SOCK` was set five hours ago still works after an agent restart, because the indirection layer absorbs the random-path change.

`$BSH_GEO_SOCK` is the only geo-related variable bsh exports by default. It contains no location data and confers no authority — peer authentication (§8.4) requires UID match and allowlist membership, neither of which the path discloses. The path is also recoverable by enumerating `/run/user/<uid>/sdi-agent.geo.path`, so withholding it from the environment would not meaningfully improve secrecy.

A `setopt BSH_GEO_NOEXPORT` option allows users who object to even this discovery hint to keep `BSH_GEO_SOCK` as a shell parameter only; in that mode `bsh-geo` inherits a one-shot-exported copy via the same mechanism §8.7 uses, and the user's parent environment carries nothing geo-related at all. See Appendix D for open questions on this option.

### 8.3 Wire Protocol

Single request, single response, then close. JSON, line-delimited, UTF-8.

**Request:**
```json
{"op":"get","require_altitude":false}
```

`op` values:

| Value | Behaviour |
| --- | --- |
| `"get"` | Return the current fix if available and authorized. |
| `"status"` | Return only metadata (provenance, accuracy, expires_at_bd) — does NOT consume the auth window or expose coordinates. |
| `"refresh"` | Ask the agent to acquire a new fix (subject to §9 trigger policy). |

`require_altitude` (optional, default `false`): if `true`, the agent MUST return `error: "altitude_unknown"` rather than serving a fix with `altitude_assumed: true`.

**Response (success):** The §6.2 payload, *minus* the `zones_entered`/`zones_exited` arrays (those are only meaningful on the push channel).

**Response (failure):** The §6.3 schema, with these additional `error` values:

| Value | Meaning |
| --- | --- |
| `"not_authorized"` | Caller's executable is not in the allowlist. |
| `"altitude_unknown"` | `require_altitude` was set and altitude is not known. |
| `"rate_limited"` | Caller is currently throttled. |

### 8.4 Peer Authentication

When a process connects to the geo socket, the agent MUST:

1. **Verify peer UID** matches the agent's effective UID via `SO_PEERCRED` (Linux), `LOCAL_PEERCRED` / `xucred` (macOS / BSD). Reject with TCP-style close on mismatch; do not respond.
2. **Resolve the peer's executable path** via `proc_pidpath(pid)` (macOS) or readlink of `/proc/<pid>/exe` (Linux). This is the **kernel's** record of the loaded executable. Argv is not consulted.
3. **Allowlist check:** the resolved path MUST appear in `~/.config/bsh/geo-allow`. If not, respond with `error: "not_authorized"` and close. Log the attempt.

   The agent canonicalizes both the resolved peer path and each allowlist entry via `realpath(3)` before comparison, so symlinked install paths (e.g. Homebrew's `/opt/homebrew/bin/bsh-geo` → `/opt/homebrew/Cellar/bsh/X.Y.Z/bin/bsh-geo`) match correctly. An allowlist entry whose `realpath` cannot be resolved is treated as not present and logged as a warning at agent startup and on reload.
4. **Optional integrity check:** if the allowlist entry includes a SHA-256 hash, the agent MUST verify the hash of the resolved executable matches before serving the fix. Mismatch → `error: "not_authorized"`, log including both hashes.
5. **Per-program approval cache:** if no current approval exists for this `(uid, exe_path, exe_hash)` tuple, the agent MAY prompt the user (Touch ID / system notification) for approval. Approval is cached in agent memory only, with a default lifetime of 300 seconds, configurable per allowlist entry. Approval expiry forces re-prompt.
6. **Rate limit:** the agent MUST limit any one peer PID to no more than 60 successful `get` requests per minute. Excess requests return `error: "rate_limited"`.

Permissions check on `~/.config/bsh/geo-allow` itself: same rules as §7.1 (mode no more permissive than `0600`, owner UID match, refuse otherwise).

### 8.5 Allowlist File Format

```
# absolute_exe_path  [sha256=<hex>]  [approve_ttl=<seconds>]
/usr/local/bin/bsh-geo
/Users/jess/bin/deploy-aware  sha256=ab12...  approve_ttl=600
/opt/iputils/bin/ping-geo
```

Lines beginning with `#` are comments. The path MUST be absolute.

---

### 8.6 The `bsh-geo` Helper

A small CLI shipped with bsh. Most callers should use this rather than speaking the raw protocol.

```
bsh-geo                    # default: ECEF, X Y Z metres, space-separated
bsh-geo --geodetic         # latitude longitude altitude (degrees, degrees, metres)
bsh-geo --bst              # BrightSpaceTime: t x y z (Bright-Seconds, BrightMeters)
bsh-geo --json             # full §6.2 payload (without zones_entered/exited)
bsh-geo --status           # provenance, accuracy_metres, seconds-until-expiry only
bsh-geo --refresh          # request a new fix, then return it
bsh-geo --refresh-presence # invalidate the presence cache (§9.3); does not return coords
bsh-geo --wait <seconds>   # if no current fix, wait up to <seconds> for one (max 30)
bsh-geo --require-altitude # exit 4 if altitude unknown rather than serving altitude_assumed
bsh-geo --audit [filter]   # query the agent's audit log; see §10.3
bsh-geo --exec -- prog ... # one-shot env injection, see §8.7
```

**Output forms:**

```
$ bsh-geo
-2294592.1 -3624318.9 4665842.4

$ bsh-geo --geodetic
47.3073 -122.2285 64.2

$ bsh-geo --bst
831492283.7 -7.6541e-3 -1.2095e-2 1.5568e-2

$ bsh-geo --status
provenance=hardware accuracy_metres=15.0 expires_in_seconds=283
```

The default form is BrightSpace ECEF in plain metres. The `--bst` form mirrors `brightdate::relativity::SpacetimeEvent` field order `(t, x, y, z)`: time first, in Bright-Seconds since J2000.0; spatial components in BrightMeters. Because `BRIGHT_METER_M = SPEED_OF_LIGHT_M_PER_S ≈ 2.998 × 10⁸`, Earth-scale spatial coordinates appear as small fractions of a BrightMeter; this is correct.

**Exit codes:**

| Code | Meaning |
| --- | --- |
| `0` | Coordinates returned. |
| `1` | Currently no fix available (`error: "expired"`, `"unavailable"`, `"denied"`, `"presence_failed"`). |
| `2` | Agent unreachable (no `BSH_GEO_SOCK`, socket connect failed, agent crashed). |
| `3` | Caller not in allowlist (`error: "not_authorized"`). |
| `4` | Altitude unknown and `--require-altitude` was set. |
| `5` | Rate limited. |

**`bsh-geo` itself MUST be present in the user's allowlist** for any of this to work; it is the canonical proxy through which ad-hoc shell scripts read location. This is the right granularity: trust the helper, not every one-off script.

### 8.6.1 The `bsh-geo-override` Helper

A sibling helper used to invoke a `command_jit`-fenced command outside its zone with audit. See §7.5.4 for full semantics. Synopsis:

```
bsh-geo-override [--reason "<text>"] -- <command> <args>...
```

Like `bsh-geo`, it MUST appear in `~/.config/bsh/geo-allow`. Unlike `bsh-geo` it does not return coordinates to its caller; it `execve`s the named command after recording an audit entry.

### 8.7 Single-Shot Environment Injection (Escape Hatch)

A small fraction of utilities cannot fork a helper or speak a socket protocol. For these, `bsh-geo` provides a one-shot exec wrapper:

```
bsh-geo --exec -- prog arg1 arg2
```

This:

1. Performs the standard authorization check **for `bsh-geo` itself**, not for `prog`. The user is authorizing `bsh-geo` to inject; they remain responsible for what `prog` does with the data.
2. Sets `BSH_LATITUDE`, `BSH_LONGITUDE`, `BSH_ALTITUDE`, `BSH_ECEF_X`, `BSH_ECEF_Y`, `BSH_ECEF_Z`, `BSH_ALTITUDE_ASSUMED`, `BSH_PROVENANCE`, `BSH_ISSUED_AT_BD`, `BSH_EXPIRES_AT_BD` in **the immediate child's environment only** (via the `execve` envp argument).
3. **Does NOT** modify the parent shell's environment. The variables exist for the lifetime of `prog` and any descendants of `prog`, and not in any other process.

This is documented as the escape hatch, not the primary path, and the RFC explicitly calls out its limitations: TTL of the variables is bounded by `prog`'s lifetime, not by the agent-controlled `expires_at_bd`. Implementors and users SHOULD prefer the socket path.

### 8.8 What Bsh Itself Does Not See

Bsh, when `BSH_GEO` is enabled, receives:

- **Zone names** (`$BSH_GEO_ZONE`, `$BSH_GEO_ZONES`) — yes.
- **Provenance** (`$BSH_GEO_PROVENANCE`) — yes.
- **Coordinates** (lat/lon/ECEF/BrightSpaceTime) — **no, not by default.** Bsh would have to query `BSH_GEO_SOCK` like any other client (and bsh would need to be in the allowlist to do so).

This means a compromise of bsh's process leaks the names of zones the user has visited this session, plus the provenance flag, plus the socket path (already exported, not sensitive). It does not leak coordinates or the geometry of any zone.

If a user genuinely wants coordinates in bsh-side parameters (for prompts, etc.), they MUST opt in via `setopt BSH_GEO_COORDS`. With that option set, bsh queries the socket like any other client and populates `$BSH_LATITUDE`, `$BSH_LONGITUDE`, `$BSH_ECEF_X`, etc. — which then live in the shell's parameter table but are still not exported.

### 8.9 Agent Restart Behaviour

§3.1 defines the registration socket as closing after handshake, with `K_session` resident in agent memory. An agent restart therefore destroys all session keys; existing shells with cached `K_session` cannot communicate with the new agent.

Bsh and other clients MUST detect agent loss and re-establish:

- **Bsh side.** Bsh detects agent loss either by an explicit OSC 7777 emit failure (the agent's reply latency exceeds 2 seconds) or by `bsh-geo` returning exit code 2 from any user invocation. On detection, bsh discards its cached `K_session`, marks the session invalid, and re-registers lazily on the next emit attempt. Until re-registration completes, bsh treats the session as having no current fix (outside all zones). User-facing behaviour: `bsh: SDI agent restarted, re-registering...` printed once to stderr; subsequent `command_jit` rules behave as if no fix is available, leading to the §7.5 advisory refusal.
- **`bsh-geo` and other clients side.** Per §8.2, clients re-read the path file once on `ECONNREFUSED` / `ENOENT` and retry the connection. After a second failure the client returns exit code 2. Clients do NOT participate in SDI session re-registration; they speak only the unauthenticated geo socket protocol (UID + allowlist gated, but not session-keyed).

The agent MUST NOT serve `geo-context` data (over either OSC 7777 or the geo socket) until at least one fix has been acquired post-restart. A query against a freshly-started agent with no fix returns `error: "unavailable"`.

### 8.10 `bsh-geo --json` Output Stability

The JSON wire format and `bsh-geo --json` output are append-only across versions: implementations MAY add fields, but MUST NOT remove or rename fields, change field types, or change the meaning of existing values, without bumping the `protocol_version` byte (§3.2). Consumers SHOULD ignore unknown fields rather than reject the payload.

The same stability guarantee applies to `--audit` JSON output (§10.3) and to the `BSH_*` environment variables set by `--exec` (§8.7).

---

## 9. Hardware Polling and Trigger Configuration

The agent does not continuously poll hardware. Acquisition is event-driven, governed by `~/.config/bsh/geo-triggers`.

### 9.1 Trigger File Format

```
# event_type  target          accuracy   ttl
session_init  *               network    1h
network_change *               network    30m
command_jit   /usr/local/bin/kubectl-prod  hardware  120s
command_jit   /opt/aws/bin/aws-prod         network   60s
```

| Field | Values |
| --- | --- |
| `event_type` | `session_init` (one fix per shell start), `network_change` (Wi-Fi/network transition), `command_jit` (just before specified command runs). |
| `target` | Absolute command path for `command_jit`; SSID or `*` for `network_change`; ignored (use `*`) for `session_init`. |
| `accuracy` | `hardware` (force GPS), `network` (Wi-Fi/IP heuristics OK), `any`. |
| `ttl` | Duration the fix is considered current. Suffixes `s`, `m`, `h`. Max 8h (matches §3 session lifetime). |

Permissions: same rules as §7.1.

**`command_jit` target distribution.** The trigger file is read by the agent, but bsh needs to know which commands to intercept *before* `execve`. To avoid duplicate parsing and config drift, the agent sends bsh the current `command_jit` target list (resolved absolute paths only — no zones, no rules) as part of the registration handshake response, and re-pushes it via OSC 7777 (`type: "sdi-config"`, payload `{"command_jit_targets":[...]}`) on every trigger-file reload. Bsh caches this list in process memory and consults it on every command resolution. Bsh does NOT read `~/.config/bsh/geo-triggers` directly.

### 9.2 `command_jit` Behaviour

When bsh is about to execute a command matching a `command_jit` rule:

1. Bsh sends a refresh request to the agent (over the established session, encrypted), naming the trigger.
2. The agent acquires hardware as required, with a **maximum wait of 5 seconds** for `network` and **15 seconds** for `hardware`. Cold GPS can exceed 15 seconds; `hardware` callers SHOULD use `accuracy: any` for non-critical paths.
3. **During the wait**, bsh prints `bsh: acquiring location for fenced command '<cmd>'...` to stderr after 1 second of elapsed wait, and updates the line periodically. Stdin is not consumed; SIGINT is honored and aborts the acquisition (treating it as `error: "unavailable"` for §7.5 purposes).
4. On success, agent pushes a `geo-context` payload over OSC 7777.
5. On timeout or `error: "unavailable"`, bsh treats this as "outside all zones" and proceeds to the §7.5 advisory check, which will refuse the command (no current fix → outside fenced zone → advisory refusal). The refusal message specifies `provenance=none, distance_metres=unknown` for clarity.
6. Bsh evaluates the advisory check per §7.5. No additional pre-exec hook is defined by this RFC; users wanting custom behaviour write a wrapper script and place it on PATH ahead of the fenced binary.

### 9.3 Presence Verification

When a zone has the `presence` option (§7.1), the agent MUST verify presence at fix time via the host's biometric API (Touch ID, Windows Hello) or, where biometrics are unavailable, an idle-time heuristic with a configurable maximum (default 30 seconds).

Presence verification is **cached for 30 seconds** by default to avoid prompt fatigue on repeated `command_jit` events. The cache lifetime is configurable via `~/.config/bsh/geo-presence-ttl` (single integer, seconds, max 300).

The cache is cleared immediately on:
- Lid close / display lock
- Explicit logout
- Agent restart
- `bsh-geo --refresh-presence`

---

## 10. Privacy and Exfil Mitigations (Geographic Context)

### 10.1 No Ambient Broadcast

Coordinates are not in `environ`, argv, `$HISTFILE`, or any file. They live in agent memory and are served per-request to authenticated, allowlisted peers.

### 10.2 No Persistence

The agent stores fixes in volatile memory only. On agent shutdown, all fixes are dropped. There is no cache file, no log file, no backup. Audit logs (§10.3) record metadata (timestamps, request counts, denial reasons) but never coordinates.

### 10.3 Audit Logging

The agent maintains an in-memory rolling log (default 1000 entries) of:

- Geo socket connection attempts, with peer PID, peer exe path, allowlist verdict.
- Approval prompts and user responses.
- Rate-limit denials.
- Zone-file and allowlist-file permission rejections.
- **`advisory_refusal` events** (per §7.5.2): bsh declined to execute a fenced command. Records `command`, `argv`, fenced `zone_name`, `distance_metres`, `accuracy_metres`, `provenance`, `issued_at_bd`.
- **`advisory_override` events** (per §7.5.4): a user invoked `bsh-geo-override` to proceed past an advisory refusal. Records all of the above plus the `--reason` text (verbatim, up to 280 chars), `reason_supplied` boolean, `reason_truncated` boolean.

The log is queryable via `bsh-geo --audit` (which itself requires allowlist membership — by default `bsh-geo` is allowlisted, and `--audit` is gated by an additional `audit=true` flag on the allowlist entry).

The audit interface supports filtering by event kind:

```
bsh-geo --audit                  # all events, JSON-Lines format (one event per line)
bsh-geo --audit refusals         # advisory_refusal only
bsh-geo --audit overrides        # advisory_override only
bsh-geo --audit denials          # not_authorized + rate_limited
bsh-geo --audit --human          # human-readable rendering, one line per event with fixed columns
bsh-geo --audit --since <bd>     # events with issued_at_bd >= <bd>
```

**Output format.** The default output of `--audit` is JSON-Lines (one JSON object per line, no array wrapper, terminated by newline). This makes the audit log trivially pipeable to `jq`, `grep`, or any line-oriented analysis tool, and it is the format `bsh-geo` itself emits when invoked from automation. The `--human` flag produces a fixed-column human-readable rendering for interactive inspection. The JSON-Lines schema is subject to the §8.10 stability guarantee.

The log MUST NOT contain coordinates, zone geometry, or the contents of `geo-context` payload bodies. It MAY contain zone names, distances, accuracies, and provenance flags as listed above. The `--reason` text is the only free-form string the agent stores; it is treated as opaque user-supplied content and is never interpreted, parsed, or matched against patterns.

Override entries are first-class: a user (or org reviewing the user's logs) can grep for them, count them, and use them as input to refining their `geo-triggers` ruleset. A rule that's overridden 30 times a week is probably the wrong rule.

### 10.4 No Wall-Clock Dependency

All timestamps on the wire are BrightDate scalars sourced from the agent's monotonic clock conversion. An attacker capable of NTP rollback cannot resurrect an expired fix because the agent's expiry check uses `mach_absolute_time` (or platform equivalent), not `gettimeofday`.

### 10.5 Provenance and Presence are Plaintext-Adjacent

`provenance` and `user_presence` ride inside the encrypted payload, so they are integrity-protected. However, they are **assertions by the agent**, not independent attestations. A user-space compromise of the agent could lie. The threat model (§5.3) excludes this case.

### 10.6 The `type` Field is Still Visible

Per §3.3, the `type` field on the OSC 7777 wire is plaintext. `geo-context` is therefore visible to any observer of the PTY stream. This RFC does not consider the *fact* that geo data is flowing to be sensitive. If you care about hiding even that, set the wire `type` to `sdi-payload` and inline `"type":"geo-context"` inside the encrypted body.

### 10.7 Defense Scope (Honesty Section)

This RFC explicitly does not defend against:

- The user themselves bypassing geo-aware checks by running `/bin/sh`, `python -c`, or any non-bsh shell.
- Malicious code already executing in the user's session under the user's UID (it can call the geo socket like any allowlisted client; allowlist defends only against unrelated processes, not co-resident malware).
- A user copying the binary they want to "fence" elsewhere or running it inside a container.
- Sensor-level spoofing (GPS spoofing, Wi-Fi BSSID spoofing). The agent reports what the OS reports.
- OS kernel compromise.

**For genuine prevention of command execution, see Appendix C.** The shell is the wrong layer for it.

---

## 11. What the Geographic Context Is Not

In plain language, restated for emphasis because the v1 draft of the geo extension caused confusion:

- **Not access control.** Bsh refuses to run a fenced command outside a zone? The user types `/bin/sh` and runs it anyway. We make this clearer; we don't pretend otherwise.
- **Not enforcement.** No "MUST block execution" appears in this RFC. The §7.5 advisory refusal is documented as friction, not a security boundary; `bsh-geo-override` makes the bypass explicit and audited rather than hidden.
- **Not anti-coercion.** A user being held at gunpoint to run `kubectl delete` from their office, where the policy permits it, will run it.
- **Not anti-malware.** Malware running as the user can read `BSH_GEO_SOCK` from `environ`, connect, fail the allowlist check, and… still do whatever else it wanted to do anyway. Geo-aware bsh is not an anti-malware product.

What it **is**:

- An **automation surface** for legitimate location-aware shell behaviour: kubeconfig switching, prompt indicators, per-zone aliases, on-arrival/on-departure scripts.
- A **privacy-preserving plumbing layer** so scripts can read location without it sprawling through `environ` and `ps`.
- A **friction layer** that catches honest mistakes ("you typed `kubectl delete` and you're in `coffee-shop`, please confirm") with an audit trail.
- A **clean integration with the BrightDate / BrightSpace / BrightSpaceTime stack** so consumer code can deserialize geo replies directly into the canonical Rust types without conversion drift.

---

## 12. Protocol Security & Threat Mitigation Profiling

This section covers SDI transport-layer threats. Geographic-context-specific privacy and exfil mitigations live in §8.

- **Rogue Injection Defense:** If an external malicious source outputs an unauthorized OSC 7777 block to stdout, the Desktop Agent intercepts the sequence, attempts validation via the mapped session key, and fails immediately at the AES-GCM Authentication Tag verification phase. The packet is dropped instantly with zero user impact.

- **Replay Defense:** The per-direction monotonic counters (§3.5), the AAD-bound `dir_tag` (§3.4), and the `issued_at` timestamp (§4) together ensure that a captured OSC 7777 sequence cannot be re-submitted to its receiver, cannot be cross-replayed in the opposite direction, and cannot be resurrected after expiry. Counter replay attempts are logged as security events.

- **AAD Boundary Confusion Defense:** Length-prefixed AAD encoding (§3.4) including the leading direction tag prevents any two distinct `(dir, counter, type, context)` tuples from producing identical AAD bytes, closing the boundary confusion attack surface present in naive concatenation.

- **Socket Squatting Defense:** Randomized socket paths and pre-bind existence checks (§3.1) prevent a malicious process from pre-occupying the socket path before the agent starts.

- **Process Ring-Fencing:** Because session encryption keys are isolated per terminal window or tab instance, background commands running concurrently in other workspaces cannot intercept, manipulate, or extract state data crossing adjacent active streams.

- **Memory-Bound Persistence (Zero Leaks):** Decrypted states are stored exclusively within the volatile memory space of the background companion daemon. Payloads automatically drop when their specified Time-To-Live metric expires or when the terminal session registers a clean exit sequence, avoiding long-term storage footprints.

- **Fail-Closed Injection:** `bsh-inject` writes directly to `/dev/tty` and refuses to operate if the agent is unavailable, preventing accidental ciphertext persistence or silent fallback to unprotected channels.

- **Type Field Visibility:** Implementors are advised that the `type` field is visible in plaintext on the PTY stream. Sensitive schema classification should be encoded within the encrypted payload body (§3.3).

---

## 13. Implementation Ecosystem & Future Directions

The reference implementation of this protocol is actively deployed and validated inside the BSH shell engine ecosystem (`bsh`), paired with a Swift-based macOS Desktop Agent (`SDIAgent`) that runs as a menu-bar background process, hosts the Unix domain socket, and routes decrypted payloads to registered application handlers.

By standardizing structured semantic pipelines, we pave the way for downstream integrations—such as secure browser plug-ins that auto-populate active web testing fields based on localized terminal history context, and unified system tray utilities that bridge CLI development speed with the accessibility of modern desktop interface tooling.

### 13.1 Browser Extension Integration — Security Considerations

Browser extension integrations **must** be treated as a distinct, high-risk trust boundary. Browser extensions operate under a significantly weaker security model than native daemons: content scripts, extension messaging APIs, and browser-controlled sandbox policies introduce attack surfaces not present in the native IPC layer defined in this RFC. Any downstream integration that routes decrypted payloads to a browser extension **must** define its own security protocol, including:

- A separate authenticated channel between the Desktop Agent and the extension (e.g. native messaging with explicit host manifest allowlisting).
- Strict scoping of which payload types are permitted to flow to the browser layer.
- An explicit threat model addressing extension compromise, malicious content scripts, and cross-origin message interception.

Treating browser extension delivery as a transparent extension of the native SDI pipeline is explicitly out of scope for this RFC and **must not** be assumed by implementors.

---

## Appendix A: Summary of Security Changes from Initial Draft

| Issue | Resolution |
| --- | --- |
| No replay protection | Monotonic counter added to OSC sequence and AAD (§3.3, §3.5) |
| AAD boundary confusion via naive concatenation | Length-prefixed AAD encoding required (§3.4) |
| Predictable socket path enables squatting | Randomized socket path + pre-bind existence check required (§3.1) |
| `bsh-inject` writes to stdout (risks log/pipe leakage) | Writes to `/dev/tty` by default; `--emit-stdout` is opt-in (§3.6) |
| No session expiry | 8-hour maximum session lifetime defined (§3.1) |
| No rate limiting on socket | 10 failed attempts/min/PID limit required (§3.2) |
| `type` field confidentiality not addressed | Advisory note added; sensitive type should be inside encrypted body (§3.3) |
| Browser extension surface unaddressed | Explicit high-risk boundary callout with required separate protocol (§13.1) |
| No agent failure handling | Fail-closed behavior defined; no silent plaintext fallback (§3.6) |
| `issued_at` absent from schemas | Required in all payload schemas; agent should validate against `ttl` (§4) |
| Wire protocol says "TCP connection" for a Unix socket | Corrected to "socket connection" throughout |

## Appendix B: Changes from v1 to v2

The v2 fork introduces bidirectional traffic over the OSC 7777 envelope and the cryptographic and protocol-version changes that bidirectionality requires.

| v1 element | v2 disposition | Rationale |
| --- | --- | --- |
| Single-direction (Shell → Agent) envelope | Bidirectional: Agent → Shell pushes share the same envelope and key (§3.3). | Required by `geo-context` (push location updates) and any future agent-pushed payload type. |
| Single per-session monotonic counter | Two independent per-direction counters: `c_shell_to_agent`, `c_agent_to_shell` (§3.5). | A single counter with two writers cannot soundly distinguish legitimate emits from replays in the opposite direction. |
| AAD covers `(counter, type, context)` | AAD covers `(dir_tag, counter, type, context)` with `dir_tag` length-prefixed (§3.4). | Cross-direction replay is impossible: GCM tag verification fails when the receiver reconstructs AAD with its direction tag. |
| Handshake: 48 bytes shell→agent, 32 bytes agent→shell | 49 / 33 bytes; first byte is `protocol_version` (§3.2). | Wire-level distinguishability of v1 and v2 sessions; agents can refuse mismatched versions before key derivation. |
| HKDF info string `"sdi-session-key"` | HKDF info string `"sdi-session-key-v2"` (§3.2). | Domain-separates v1 and v2 keys so a version-mismatch handshake produces incompatible keys rather than silent cross-version traffic. |
| Mixed-version sessions | Not supported (§3.2). | Two protocols sharing a session would re-introduce the counter-collision and direction-replay risks v2 closes. |

v2 retains all v1 security properties (Appendix A) and adds the above. Implementations that do not need agent-pushed traffic MAY continue to target v1 indefinitely; v2 is required for any scenario where the agent emits sequences to the shell.

---

## Appendix C — Tier 2 Enforcement (Informational, Non-Normative)

This appendix sketches how a future privileged component would deliver actual prevention of command execution, sharing this RFC's policy file format and `geo-context` payload schema.

### C.1 macOS: EndpointSecurity Client

A separate daemon, sibling to SDIAgent, registers as an EndpointSecurity client and authorizes `ES_EVENT_TYPE_AUTH_EXEC` events. On each exec:

1. ES daemon receives the event with full process metadata.
2. Daemon consults a policy file (format compatible with §7.1 zone definitions plus an `enforce-on:` clause naming executables to gate).
3. Daemon queries SDIAgent (or shares its memory) for the current `geo-context`.
4. If the policy denies, daemon returns `ES_AUTH_RESULT_DENY` and the kernel never starts the process.

This requires the `com.apple.developer.endpoint-security.client` entitlement, root privileges, system-extension installation, and notarization. Latency budget is tight (hundreds of microseconds) and fail-open vs fail-closed semantics need careful design.

### C.2 Linux: eBPF LSM or fanotify

An eBPF LSM program attached to `bprm_check_security` can deny `execve` based on the same policy. fanotify with `FAN_OPEN_EXEC_PERM` is a more portable alternative. Both require root / `CAP_SYS_ADMIN`.

### C.3 What Tier 2 Inherits From This RFC

- The `~/.config/bsh/geo-zones` format (or a `/etc/bsh/geo-zones` system equivalent for sysadmin-imposed policy).
- The `geo-context` payload schema (§6.2).
- The agent's coordinate-conversion authority.
- The provenance and presence semantics.

What changes for Tier 2:

- The policy file lives under `/etc/` and is root-owned, mode `0644`.
- The verdict applies to *every* `execve` system-wide, regardless of which shell or interpreter initiated it. Bsh becomes one consumer of the policy among many.
- `enforce-on:` clauses become real enforcement, not advisory friction.

Tier 2 is a **separate project**. Its protocol and ABI compatibility with Tier 1 are intentional design goals so that Tier 1's authoring effort is not wasted when Tier 2 ships.

---

## Appendix D — Open Questions (Geographic Context)

1. **`bsh-geo --exec` `BSH_*` env names.** Field names chosen for §8.7 may collide with existing user conventions. Should we namespace under `BSH_GEO_*` instead (`BSH_GEO_LATITUDE`, etc.)? Marginally longer; less collision risk. Lean: namespace under `BSH_GEO_*`. Holding for review.

2. **Multi-zone overlap.** What if the user is in `office` and `building-7` simultaneously (overlapping radii)? §7.3 says `$BSH_GEO_ZONE` is the *newest entered*; `$BSH_GEO_ZONES` enumerates all matched. Confirmed reasonable, but worth a usability pass once we have a real user.

3. **Allowlist hash algorithm agility.** §8.4 specifies SHA-256. Future-proofing against post-quantum / collision concerns suggests `algo=sha256:<hex>` syntax allowing future `sha3-256:`, `blake3:`, etc. Cheap to add now; lean toward `algo=` prefix syntax, keeping `sha256=<hex>` as a deprecated shorthand for one release.

4. **`setopt BSH_GEO_NOEXPORT` semantics.** §8.2 sketches an option to keep `BSH_GEO_SOCK` out of the exported environment entirely. Open: under that option, what happens for indirect children (e.g. a script invoked by a script that itself wasn't a direct `bsh-geo --exec` invocation)? The cleanest answer is "they don't have geo access," which is also the most surprising. Alternative: a small forwarding table keyed by session ID, served by the agent, so any process under the user's bsh process tree can still reach the agent if it explicitly asks. Punting until we know whether anyone actually wants this option.

5. **Trigger script PATH.** §7.4 sanitized environment passes through `PATH`. Should it instead set a known-good PATH (`/usr/local/bin:/usr/bin:/bin`)? Pro: stops `PATH` injection from a parent compromise. Con: surprises users whose triggers depend on their PATH. Lean: known-good PATH, document the override.

These are deliberately punted to review rather than guessed at.

**Resolved during v2 review** (no longer open):

- ~~Override exit code~~ — settled at `124` in §7.5.2.
- ~~`geo-context` over OSC 7777 vs registration socket~~ — pushes go over OSC 7777 with v2's bidirectional envelope; registration socket remains a one-shot per §3.1.
- ~~`bsh-geo --json` stability~~ — append-only across versions per §8.10.
- ~~`--audit` output format~~ — JSON-Lines by default, `--human` for interactive inspection (§10.3).
- ~~Trigger filename plurality~~ — `~/.config/bsh/geo-triggers` (plural) per §9.1.
