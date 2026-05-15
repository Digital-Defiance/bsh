#!/usr/bin/env python3
"""Decrypt an AES-256-GCM ciphertext, all inputs via environment variables.

Environment variables (all required):
  SDI_KEY   - session key as hex string (64 hex chars = 32 bytes)
  SDI_NONCE - nonce as base64url-padded string (16 chars = 12 bytes)
  SDI_CT    - ciphertext as base64-padded string
  SDI_TAG   - authentication tag as base64-padded string (24 chars = 16 bytes)
  SDI_AAD   - additional authenticated data as plain string (may be empty)

Writes decrypted plaintext to stdout; exits 0 on success, 1 on any error.
Used by V16sdi.ztst round-trip decryption tests.
"""
import base64, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key   = bytes.fromhex(os.environ['SDI_KEY'])
nonce = base64.b64decode(os.environ['SDI_NONCE'])
ct    = base64.b64decode(os.environ['SDI_CT'])
tag   = base64.b64decode(os.environ['SDI_TAG'])
aad_s = os.environ.get('SDI_AAD', '')
aad   = aad_s.encode() if aad_s else None

plain = AESGCM(key).decrypt(nonce, ct + tag, aad)
sys.stdout.buffer.write(plain)
