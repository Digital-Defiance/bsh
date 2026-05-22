---
title: "Announcing BrightLink: short-lived credentials should live in a menu bar, not your shell history"
date: 2026-05-22
author: Jessica Mulein
---

# Announcing BrightLink

There's a kind of secret you handle a hundred times a day and never think
of as a secret: the AWS STS token your `aws-vault exec` just minted, the
DB password your `kubectl exec` pulled from a sealed secret, the OAuth
bearer your `gh auth token` printed for that one curl. They live for
ten minutes. They die quietly. Most of them never see a password
manager — password managers are for the credentials you'd type with two
hands and an authenticator code.

Those ten-minute credentials still need to *go somewhere*. The
default place they go is one of:

```
export AWS_SESSION_TOKEN=...
```

…which writes the secret into the environment of every child process,
forever, where it can be picked up by tmux scrollback, shell history,
debug-mode logs, or anything that snapshots `/proc/self/environ`. The
credential lives wherever those things live. Which is much longer than
ten minutes.

I built **BrightLink** because I think those credentials deserve a
better default home: a small menu-bar app that holds them in memory for
exactly as long as their declared TTL, surfaces them as click-to-copy
items, and forgets them when they expire.

## What BrightLink is

BrightLink is a Unix-socket protocol between CLI tools (the **shell**)
and a single resident desktop agent (the **bridge**). On macOS the
bridge is **BrightNexus**, a SwiftUI menu-bar app. Each shell
registers once, anchoring its session in a hardware-signed transcript
that the shell verifies before trusting the bridge's identity. After
registration, the shell delivers credential payloads as authenticated
AES-256-GCM ciphertexts over the same socket. The bridge surfaces those
credentials in a menu-bar UI scoped to their declared TTL: when the
credential expires, it disappears.

The protocol is greenfield. There is no clipboard hop, no terminal
emulator participation, no daemon plurality, and no string-rich text
format that has to be parsed out of a stream. Everything the bridge
sees is a JSON object on a Unix socket, AEAD-tagged under a session key
derived from a hardware-rooted handshake.

A working bsh session looks like:

```bsh
zmodload bsh/brightlink

# get a credential from somewhere — STS, vault, gh auth, anywhere.
$(aws-vault exec prod -- aws sts get-session-token | \
  jq -r '"{\"provider\":\"aws\",\"accessKeyId\":\"\(.Credentials.AccessKeyId)\",\
    \"secretAccessKey\":\"\(.Credentials.SecretAccessKey)\",\
    \"sessionToken\":\"\(.Credentials.SessionToken)\",\"ttl\":3600}"' \
  | bsh-inject --type cloud-session --context aws://prod)
```

That credential now lives in BrightNexus's menu bar with a 1-hour TTL
countdown. It's never been in your environment. It's never been in
your history. It's never been in your scrollback.

## Why it isn't a password manager

Long-lived secrets — your GitHub PAT, your production DB password,
your password-manager master password — belong in a password manager:
an agent that asks for explicit consent on every read, that the user
trusts to outlive any one terminal session, and that's worth the
friction of a master-password unlock.

BrightLink is the opposite: it's for credentials that live for ten
minutes. Asking for consent on every read produces a workflow nobody
will use. So BrightLink doesn't.

What it has instead is:

- **A hard TTL ceiling.** A user-configurable cap (1 hour by default,
  range 1–480 minutes) below which every credential's declared TTL is
  silently clamped. A bug in a tool that asks for a 24-hour TTL
  produces a credential that lives 1 hour, not 24.
- **Session-scoped storage.** Credentials live in the bridge's memory.
  Nothing touches disk. Closing the menu-bar app evicts everything
  immediately.
- **Optional peer attestation.** The bridge can be configured to
  reject deliveries from any binary that fails codesign attestation.
  Off by default (it's annoying for in-development tools), but available
  for hardened environments.
- **Direction-bound AAD.** Each ciphertext is bound to its direction
  and its monotonic counter at the AEAD layer. Replay an old
  ciphertext to the bridge, replay it across direction tags, alter
  the type or context — every one fails the GCM tag check.

It's a small surface area. That's the point. Most of what makes
password managers heavy is the long-lived storage commitment. We don't
have one.

## Why it's hardware-anchored

The bridge's identity is anchored in Apple's Secure Enclave. The
registration transcript is signed by an SEP-resident P-256 key whose
private half *cannot* leave the hardware. Even root can't read it.
The shell verifies that signature on every registration and pins the
SEP key on first use.

This bounds a class of attacks I worry about: a malicious binary
masquerading as BrightNexus on the same socket path. To impersonate a
real BrightNexus install, an attacker needs to either compromise the
SEP itself (a much higher bar than "user runs a malicious binary") or
catch a fresh device before the user has ever run the real thing. The
latter is a real but narrow attack window — the kind of thing a future
out-of-band SEP-key publication via Apple's notarization records can
close further.

Hardware anchoring also means the bridge identity is *device*-scoped.
Move BrightNexus to a different Mac and it's a different identity.
That's how it should be.

## What's in v1 and what's coming

v1 ships two implemented commands:

- `LINK_REGISTER` — the §4.5 handshake. Bilateral HKDF, 238-byte
  SEP-signed transcript, TOFU pin, 8-hour session TTL.
- `LINK_DELIVER` — Shell → Agent credential delivery. AES-256-GCM
  with length-prefixed AAD binding direction, counter, type, and
  context. Replay window of 1000.

It reserves five more for future drafts:

- `LINK_PUSH` — Agent → Shell push subscription. Lets the bridge
  proactively deliver credentials *back* to a registered shell. Useful
  for things like "your zone changed; here's the new geo-context
  payload."
- `LINK_GEO_GET` / `LINK_GEO_STATUS` / `LINK_GEO_REFRESH` /
  `LINK_GEO_AUDIT` — geo-context surface. Zone-scoped credential
  delivery driven by location fixes. Useful for the
  "this credential only works inside this physical zone" use case.
- `LINK_AUDIT_EMIT` — bulk audit export. Compliance hook.

These reserved commands return a stable
`"<command> not implemented in this build"` error string so v1-aware
clients can detect a bridge that knows the surface but hasn't shipped
the implementation. v1.x will fill them in.

## Standardised payload schemas

Nine credential schemas are defined in v1, each with its own
plaintext shape:

- `ephemeral-auth` — username/password/email
- `db-connection` — engine/host/port/user/pass
- `api-token` — bearer token + scopes
- `cloud-session` — STS-shaped (provider/access-key/secret/session-token/region)
- `ssh-credential` — host/user/private-key/passphrase
- `kubeconfig-context` — cluster/server/CA/user/cert/key/token
- `totp-seed` — TOTP secret + algorithm/digits/period
- `mtls-cert` — client cert + key + CA bundle
- `plaintext` — generic single-value carrier (label/value/masked)

Agents MAY accept additional types under their own namespace and MUST
ignore unknown types. The schema set is loose enough to fit the
"credential-shaped thing my tool produces" without forcing a specific
ecosystem.

## Where to get it

- **bsh** (the shell with `bsh-inject`):
  https://bsh.digitaldefiance.org · https://github.com/Digital-Defiance/bsh
- **BrightNexus** (the macOS bridge):
  https://brightnexus.brightdate.org · https://github.com/Digital-Defiance/BrightNexus
- **enclave-bridge-client** (the TypeScript client for non-bsh integrations):
  https://github.com/Digital-Defiance/enclave-bridge-client
- **BrightLink v1 RFC**:
  https://github.com/Digital-Defiance/bsh/blob/main/docs/rfc-brightlink.md
- **Test harness with conformance vectors and mock bridge/client**:
  https://github.com/Digital-Defiance/bsh/tree/main/test-harness

## What I'd love feedback on

A few things I'm not sure about:

1. **The schema set.** Is `ssh-credential` shaped right? Is
   `kubeconfig-context` shaped right? These are the schemas I needed
   for my workflows; if you have workflows I haven't thought of, I'd
   love to know what they need.

2. **The TTL ceiling default.** 1 hour feels right for a developer
   tool; it's also kind of arbitrary. If you have data on what
   ephemeral-credential lifetimes actually look like in production
   workflows, I'd love to hear it.

3. **Linux/Windows bridges.** v1 is macOS / Apple Silicon only because
   that's what I run. The protocol is platform-agnostic — anyone
   building a TPM-backed Linux bridge or a DPAPI-backed Windows
   bridge should land cleanly. If you're up for that, please yell.

If you build something with this, I'd love to hear about it. If you
break something with this, I'd love to hear about that even more.

— Jessica Mulein
