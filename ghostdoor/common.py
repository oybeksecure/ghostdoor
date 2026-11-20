"""Shared knock-packet format for Ghost Door.

Knock packet (51 bytes, sent over UDP):
    MAGIC(3) | timestamp_ms(8) | nonce(8) | HMAC-SHA256(32)

The HMAC covers MAGIC + timestamp + nonce, keyed with a shared secret.
The server NEVER answers a knock (valid or not), so a scanner cannot tell
that a knock listener exists at all.
"""
import hashlib
import hmac
import os
import struct
import time

MAGIC = b"GD1"
HEADER = struct.Struct("!3sQQ")          # magic, ts_ms, nonce
PACKET_LEN = HEADER.size + 32            # + HMAC-SHA256

DEFAULT_SECRET = "change-me-demo-secret"
DEFAULT_KNOCK_PORT = 9999   # UDP: silent knock listener
DEFAULT_VAULT_PORT = 9000   # TCP: real service, CLOSED until a valid knock
DEFAULT_DECOY_PORT = 9001   # TCP: always-open fake service (tarpit)
DEFAULT_WEB_PORT = 8080     # dashboard


def build_knock(secret: str, ts_ms: int | None = None, nonce: int | None = None) -> bytes:
    if ts_ms is None:
        ts_ms = int(time.time() * 1000)
    if nonce is None:
        nonce = int.from_bytes(os.urandom(8), "big")
    header = HEADER.pack(MAGIC, ts_ms, nonce)
    mac = hmac.new(secret.encode(), header, hashlib.sha256).digest()
    return header + mac


def verify_knock(secret: str, packet: bytes, max_skew_s: float = 10.0):
    """Return (status, nonce). status is one of:
    ok | malformed | badsig | stale   (replay is detected by the server, which
    remembers nonces)."""
    if len(packet) != PACKET_LEN:
        return "malformed", None
    header, mac = packet[:HEADER.size], packet[HEADER.size:]
    magic, ts_ms, nonce = HEADER.unpack(header)
    if magic != MAGIC:
        return "malformed", None
    expected = hmac.new(secret.encode(), header, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        return "badsig", nonce
    if abs(time.time() - ts_ms / 1000.0) > max_skew_s:
        return "stale", nonce
    return "ok", nonce
