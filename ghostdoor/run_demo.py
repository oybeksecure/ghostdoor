#!/usr/bin/env python3
"""Automated end-to-end demo / test. Starts the server, plays defender and
attacker (using 127.0.0.2 = defender, 127.0.0.3 = attacker), prints PASS/FAIL."""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from common import DEFAULT_SECRET, build_knock
from knock import send_knock
from scanner import scan, grab_banner
from vault_client import connect

GOOD, BAD, H = "127.0.0.2", "127.0.0.3", "127.0.0.1"
WINDOW = 6
fails = []


def check(name, cond, extra=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name} {extra}")
    if not cond:
        fails.append(name)


def vault_refused(src):
    """True if the attacker gets no vault banner: either the kernel refuses the
    connection (door closed) or the server resets it right after the handshake
    (door open for someone else, but not for this IP)."""
    try:
        s = connect(H, 9000, src, 1)
    except (ConnectionRefusedError, OSError):
        return True
    try:
        return not s.recv(100).startswith(b"GHOST-VAULT")
    except (ConnectionResetError, OSError):
        return True
    finally:
        s.close()


srv = subprocess.Popen([sys.executable, os.path.join(HERE, "server.py"), "--window", str(WINDOW),
                        "--tarpit-interval", "0.5", "--log", os.path.join(HERE, "demo_events.jsonl")],
                       cwd=HERE, stdout=subprocess.DEVNULL)
time.sleep(1.0)
try:
    print("\n1) Attacker scans the host")
    res = scan(H, [9000, 9001, 9999, 8888], BAD, 0.3)
    print("    ", res)
    check("vault port 9000 looks CLOSED to the attacker", res[9000] == "closed")
    check("decoy port 9001 looks open", res[9001] == "open")

    print("2) Attacker grabs the decoy banner -> tarpit")
    data, secs = grab_banner(H, 9001, BAD, patience=3)
    check("attacker held in tarpit for >=3s", secs >= 3, f"({secs:.1f}s, got {len(data)} junk bytes)")

    print("3) Legit client knocks from the defender IP")
    check("before knock: vault refused for defender", vault_refused(GOOD))
    pkt = send_knock(H, 9999, DEFAULT_SECRET, GOOD)
    time.sleep(0.4)
    s = connect(H, 9000, GOOD)
    banner = s.recv(200).decode()
    check("after knock: vault banner received", banner.startswith("GHOST-VAULT"))
    s.sendall(b"GET flag\n")
    flag = s.recv(200).decode().strip()
    check("secret readable by authenticated client", flag.startswith("FLAG{"), flag)
    s.close()

    print("4) Attacker sniffs the knock and replays it from his own IP")
    send_knock(H, 9999, "", BAD, packet=pkt)
    time.sleep(0.4)
    check("replayed knock does NOT open door for attacker", vault_refused(BAD))

    print("5) Attacker forges a knock with a guessed secret")
    send_knock(H, 9999, "wrong-secret", BAD)
    time.sleep(0.4)
    check("forged knock rejected", vault_refused(BAD))

    print("6) Knock to the UDP port gets no reply (silent)")
    import socket
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(0.7)
    u.sendto(build_knock(DEFAULT_SECRET), (H, 9999))
    try:
        u.recvfrom(100)
        silent = False
    except socket.timeout:
        silent = True
    check("server never replies to knocks", silent)

    print(f"7) Wait for the {WINDOW}s window to expire")
    time.sleep(WINDOW + 1)
    check("door closed again for the defender", vault_refused(GOOD))
finally:
    srv.terminate()

print("\nRESULT:", "ALL PASS" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
