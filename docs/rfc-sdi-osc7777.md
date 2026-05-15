# RFC: Secure Semantic Data Injection (SDI) via OSC 7777 Escape Sequences

**Author:** Jessica Mulein

**Status:** Proposal / Draft Standard

**Date:** May 2026

------

## 1. Abstract

Modern terminal workflows routinely interact with, generate, and process multi-field, highly structured ephemeral data—such as dynamic test credentials, cloud session authentication elements, and complex infrastructure connection contexts.

However, the protocol layer interfacing terminal emulator tasks with the host operating system remains restricted to flat text streaming or unsecured, single-value system clipboards. This document proposes an open, cross-platform standard for Secure Semantic Data Injection (SDI) using a new operating system command sequence (OSC 7777), enabling isolated, cryptographically validated pipeline structures to communicate typed JSON states natively between shells and background companion applications without risking clipboard exposure or text-forgery attacks.

------

## 2. The Problem & The Vulnerability Vector

### 2.1 Limitations of the System Clipboard

Passing rich structural schemas (such as a username, password, and seed phrase simultaneously) via the native OS clipboard forces an unideal developer compromise: either concatenating strings into fragile formats, manually copying individual fields iteratively, or leaking sensitive credentials to local background clipboard manager histories.

### 2.2 Terminal Line Hijacking & Rogue Code Execution

Relying on standard unauthenticated Operating System Commands (OSC) to communicate with native desktop applications poses a severe security hazard. If a terminal environment blindly parses and acts upon plaintext escape sequences embedded within standard output, any untrusted asset—such as a malicious repository file evaluated via cat, a deceptive git commit log, or an unvetted server Message of the Day (MOTD)—can forge sequences to inject structural data or trigger unintended desktop-agent side-effects.

------

## 3. Architecture Specification

The Secure SDI standard introduces a distinct decoupled separation between the Transport Vector (the PTY text pipeline) and the Authentication Control Layer (an out-of-band IPC handshake).

### 3.1 Out-of-Band Cryptographic Registration

Before any data injection takes place, an interactive shell session registers itself with a localized, user-restricted background Desktop Agent Daemon running on the host system.

1. **Local Channel:** The Agent hosts a restricted Unix domain socket or cross-platform equivalent accessible exclusively by the local user account (chmod 600).
2. **Ephemeral Exchange:** The shell instance connects to the socket during its initialization phase and negotiates a unique short-lived symmetric encryption key ($K_{session}$) alongside a transient Session-ID.
3. This key resides strictly within the active memory space of that specific shell process and the Desktop Agent.

### 3.2 The Secure OSC 7777 Sequence Syntax

When a utility or process inside the shell wants to broadcast structured semantic data, it wraps the payload inside an encrypted OSC 7777 macro structure:

\e]7777;[Session-ID];[Base64-Nonce];[Base64-Ciphertext];[Base64-Auth-Tag]\a

- \e]7777;: Standard Escape and Operating System Command marker indicating the Semantic Data Injection protocol.
- [Session-ID]: A plaintext unique identifier mapping the incoming sequence to the specific originating TTY session registration.
- [Base64-Nonce]: A unique 12-byte initialization vector ensuring cryptographic uniqueness per sequence.
- [Base64-Ciphertext]: An AES-256-GCM encrypted JSON string payload containing typed data attributes.
- [Base64-Auth-Tag]: A 16-byte authentication block utilized to verify payload integrity and origin authenticity.
- \a: Standard string terminator (BEL or ST).

------

## 4. Standardized Payload Schemas

To maintain universal compatibility across browser extensions, form fillers, and desktop application management panels, payloads must adhere to predictable, strongly-typed semantic JSON specifications.

### 4.1 ephemeral-auth

Targeted at seeding short-lived accounts, hotseat multiplayer testing matrices, and web environment login flows.

JSON

```
{
  "type": "ephemeral-auth",
  "context": "http://localhost:3005",
  "ttl": 300,
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

JSON

```
{
  "type": "db-connection",
  "context": "development-cluster-alpha",
  "ttl": 60,
  "data": {
    "engine": "postgresql",
    "host": "127.0.0.1",
    "port": 5432,
    "user": "db_admin",
    "pass": "ephemeral_token_string"
  }
}
```

------

## 5. Security & Threat Mitigation Profiling

- **Rogue Injection Defense:** If an external malicious source outputs an unauthorized OSC 7777 block to stdout, the Desktop Agent intercepts the sequence, attempts validation via the mapped session key, and fails immediately at the AES-GCM Authentication Tag verification phase. The packet is dropped instantly with zero user impact.
- **Process Ring-Fencing:** Because session encryption keys are isolated per terminal window or tab instance, background commands running concurrently in other workspaces cannot intercept, manipulate, or extract state data crossing adjacent active streams.
- **Memory-Bound Persistence (Zero Leaks):** Decrypted states are stored exclusively within the volatile memory space of the background companion daemon. Payloads automatically drop when their specified Time-To-Live metric expires or when the terminal session registers a clean exit sequence, avoiding long-term storage footprints.

------

## 6. Implementation Ecosystem & Future Directions

The reference implementation of this protocol is currently actively deployed and validated inside the BSH shell engine ecosystem, paired with an open-source Go/Rust background runtime suite.

By standardizing structured semantic pipelines, we pave the way for downstream integrations—such as secure browser plug-ins that auto-populate active web testing fields based on localized terminal history context, and unified system tray utilities that bridge CLI development speed with the accessibility of modern desktop interface tooling.