#!/usr/bin/env python3
"""Attacker tools against the knock: replay a captured packet, or forge one
with a guessed secret. Both should FAIL. Own lab only."""
import argparse

from common import DEFAULT_KNOCK_PORT, build_knock
from knock import send_knock

p = argparse.ArgumentParser()
p.add_argument("mode", choices=["replay", "forge", "stale"])
p.add_argument("--hex", help="captured packet (hex) for replay mode")
p.add_argument("--host", default="127.0.0.1")
p.add_argument("--port", type=int, default=DEFAULT_KNOCK_PORT)
p.add_argument("--src")
a = p.parse_args()

if a.mode == "replay":
    pkt = bytes.fromhex(a.hex)
elif a.mode == "forge":
    pkt = build_knock("attacker-guessed-secret")
else:  # old but correctly signed packet (needs the real secret: simulates a very late replay)
    import time
    from common import DEFAULT_SECRET
    pkt = build_knock(DEFAULT_SECRET, ts_ms=int((time.time() - 60) * 1000))
send_knock(a.host, a.port, "", a.src, packet=pkt)
print(f"{a.mode} packet sent - check the dashboard: it should be rejected")
