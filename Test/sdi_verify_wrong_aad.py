#!/usr/bin/env python3
"""Verify that a wrong AAD causes AES-256-GCM authentication failure.

Environment variables (all required):
  SDI_KEY       - session key as hex string (64 hex chars = 32 bytes)
  SDI_NONCE     - nonce as base64-padded string (16 chars = 12 bytes)
  SDI_CT        - ciphertext as base64-padded string
  SDI_TAG       - authentication tag as base64-padded string
  SDI_WRONG_AAD - the *incorrect* AAD to use (must cause InvalidTag)

Exits 0 if decryption raises InvalidTag (expected), 1 if it unexpectedly
succeeds (rogue injection would have been accepted).
Used by V16sdi.ztst RFC §5 rogue-injection defense test.
"""
import base64, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

key   = bytes.fromhex(os.environ['SDI_KEY'])
nonce = base64.b64decode(os.environ['SDI_NONCE'])
ct    = base64.b64decode(os.environ['SDI_CT'])
tag   = base64.b64decode(os.environ['SDI_TAG'])
aad   = os.environ['SDI_WRONG_AAD'].encode()

try:
    AESGCM(key).decrypt(nonce, ct + tag, aad)
    sys.exit(1)   # must not reach here: wrong AAD must invalidate the tag
except (InvalidTag, Exception):
    sys.exit(0)   # expected: GCM authentication tag verification fails
