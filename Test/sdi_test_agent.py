#!/usr/bin/env python3
"""
sdi_test_agent.py – minimal Desktop Agent stub for V16sdi.ztst

Listens on a Unix domain socket, performs the X25519 ECDH handshake
exactly as the production Desktop Agent would, then waits for the shell
to close the connection.

Usage:
  python3 sdi_test_agent.py <socket_path> <ready_file>

The agent creates <socket_path>, writes a single newline to <ready_file>
(creating it) to signal readiness, handles one connection, then exits.

On success it prints the 32-hex-char session_id it received to stdout,
which the test uses to cross-check the OSC 7777 output.

Requires: Python >= 3.6 and the 'cryptography' package.
"""

import os
import socket
import struct
import sys

def main():
    if len(sys.argv) != 3:
        sys.exit("usage: sdi_test_agent.py <socket_path> <ready_file>")

    sock_path  = sys.argv[1]
    ready_file = sys.argv[2]

    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, PrivateFormat, NoEncryption)
        import hmac as _hmac, hashlib
    except ImportError:
        sys.exit("cryptography package not available – skipping")

    # Remove stale socket if present.
    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    os.chmod(sock_path, 0o600)
    srv.listen(1)

    # Signal readiness.
    with open(ready_file, "w") as fh:
        fh.write("\n")

    conn, _ = srv.accept()
    srv.close()

    try:
        # Read session_id (16 B) + shell's X25519 public key (32 B).
        wire = b""
        while len(wire) < 48:
            chunk = conn.recv(48 - len(wire))
            if not chunk:
                sys.exit("agent: unexpected EOF during handshake")
            wire += chunk

        session_id  = wire[:16]
        shell_pub   = wire[16:48]

        # Generate agent ephemeral X25519 key and send public key back.
        agt_priv = X25519PrivateKey.generate()
        agt_pub  = agt_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        conn.sendall(agt_pub)

        # Derive shared secret and session key (HKDF-SHA256, single block).
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        shell_key = X25519PublicKey.from_public_bytes(shell_pub)
        shared    = agt_priv.exchange(shell_key)

        # HKDF-SHA256 extract (PRK = HMAC-SHA256(salt=session_id, IKM=shared))
        prk = _hmac.new(session_id, shared, hashlib.sha256).digest()
        # HKDF-SHA256 expand single block (T1 = HMAC-SHA256(PRK, info || 0x01))
        info = b"sdi-session-key"
        session_key = _hmac.new(prk, info + b"\x01", hashlib.sha256).digest()

        # Emit the session_id as hex so the test can compare it.
        print(session_id.hex(), flush=True)

        # Emit the derived session key as hex so the test can decrypt.
        print(session_key.hex(), flush=True)

    finally:
        conn.close()

    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass

if __name__ == "__main__":
    main()
